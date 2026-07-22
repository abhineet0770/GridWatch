"""
GridWatch CLI main entry point.
Uses typer for CLI definition. For Phase 4, it initializes the ModbusParser,
maintains register states, checks alert rules, and logs security alerts and traffic details
to a local log file in JSON lines format.
"""

import json
import logging
import os
from typing import Any

import pyshark
import typer

try:
    from gridwatch import config
    from gridwatch.alert_dedup import AlertDeduplicator
    from gridwatch.alert_rules import check_rules
    from gridwatch.modbus_parser import ModbusParser, RemoteModbusCapture
except ImportError:
    import config
    from alert_dedup import AlertDeduplicator
    from alert_rules import check_rules
    from modbus_parser import ModbusParser, RemoteModbusCapture

PacketData = dict[str, Any]

app = typer.Typer(help="GridWatch: Passive OT Network Security Monitoring Tool")

logger = logging.getLogger("gridwatch")


def setup_logging() -> logging.Logger:
    """Configure the JSON lines log file handler for security and audit trails."""
    os.makedirs(config.LOG_DIR, exist_ok=True)

    logger = logging.getLogger("gridwatch")
    logger.setLevel(logging.INFO)

    # Avoid duplicate handlers if setup_logging is called multiple times
    if logger.hasHandlers():
        logger.handlers.clear()

    file_handler = logging.FileHandler(config.LOG_FILE_PATH, encoding="utf-8")
    file_handler.setLevel(logging.INFO)

    # Format log entries as plain messages (JSON serializations)
    formatter = logging.Formatter("%(message)s")
    file_handler.setFormatter(formatter)

    logger.addHandler(file_handler)
    return logger


def print_parsed_packet(parsed_packet: PacketData) -> None:
    """Format and display parsed Modbus TCP packet details to the console."""
    ts = parsed_packet["timestamp"].strftime("%Y-%m-%d %H:%M:%S.%f")[:-3]
    direction_arrow = "-->" if parsed_packet["direction"] == "request" else "<--"

    header = f"[{ts}] {parsed_packet['src_ip']} {direction_arrow} {parsed_packet['dst_ip']}"
    meta = f"FC: {parsed_packet['func_code']:02d} | TransID: {parsed_packet['trans_id']}"

    typer.echo(
        f"{typer.style(header, fg=typer.colors.GREEN)} | {typer.style(meta, fg=typer.colors.CYAN)}"
    )

    if parsed_packet["registers"]:
        reg_details = ", ".join(
            f"Reg {register}: {value}" for register, value in parsed_packet["registers"].items()
        )
        typer.echo(f"  {typer.style('Mapped Registers:', fg=typer.colors.YELLOW)} {reg_details}")
    elif parsed_packet["values"]:
        val_details = ", ".join(map(str, parsed_packet["values"]))
        typer.echo(f"  {typer.style('Raw Values:', fg=typer.colors.MAGENTA)} [{val_details}]")
    elif parsed_packet["direction"] == "request" and parsed_packet["ref_num"] is not None:
        typer.echo(
            f"  {typer.style('Read Request starting from:', fg=typer.colors.WHITE)} "
            f"Reg {parsed_packet['ref_num']}"
        )


def print_alert(alert: PacketData) -> None:
    """Display a triggered security alert to the console with color-coded severity."""
    ts = alert["timestamp"].strftime("%Y-%m-%d %H:%M:%S.%f")[:-3]
    severity_str = f"[{alert['severity']}]"
    rule_info = f"Rule: {alert['rule_id']}"

    if alert["severity"] == "CRITICAL":
        prefix = typer.style(
            f"!!! {severity_str} {rule_info} !!!",
            fg=typer.colors.WHITE,
            bg=typer.colors.RED,
            bold=True,
        )
        desc = typer.style(alert["description"], fg=typer.colors.RED, bold=True)
    else:  # HIGH
        prefix = typer.style(
            f"[!] {severity_str} {rule_info} [!]",
            fg=typer.colors.BLACK,
            bg=typer.colors.YELLOW,
            bold=True,
        )
        desc = typer.style(alert["description"], fg=typer.colors.YELLOW, bold=True)

    typer.echo(f"{prefix} {typer.style(f'@{ts}', fg=typer.colors.CYAN)}")
    typer.echo(f"  {desc}")


def build_traffic_log_entry(parsed_packet: PacketData) -> PacketData:
    return {
        "timestamp": parsed_packet["timestamp"].isoformat(),
        "event": "traffic",
        "src_ip": parsed_packet["src_ip"],
        "dst_ip": parsed_packet["dst_ip"],
        "direction": parsed_packet["direction"],
        "func_code": parsed_packet["func_code"],
        "trans_id": parsed_packet["trans_id"],
        "registers": {
            str(register): value for register, value in parsed_packet["registers"].items()
        },
    }


def build_alert_log_entry(alert: PacketData) -> PacketData:
    return {
        "timestamp": alert["timestamp"].isoformat(),
        "event": "alert",
        "rule_id": alert["rule_id"],
        "severity": alert["severity"],
        "description": alert["description"],
        "src_ip": alert["src_ip"],
        "dst_ip": alert["dst_ip"],
    }


def process_packet(
    parsed_packet: PacketData,
    state: PacketData,
    *,
    emit_azure: bool = True,
    deduplicator: Any = None,
) -> list[PacketData]:
    """Shared per-packet processing pipeline: update process state dict, evaluate rules (R001-R004),
    and return list of triggered alerts.
    """
    return check_rules(state, parsed_packet, emit_azure=emit_azure, deduplicator=deduplicator)


def format_watch_state_line(parsed_packet: PacketData, state: PacketData) -> str:
    """Format a timestamped live process state line with R001 readiness evaluation."""
    ts = parsed_packet["timestamp"].strftime("%Y-%m-%d %H:%M:%S.%f")[:-3]

    pressure_val = state.get("reactor_pressure")
    press_str = f"{pressure_val}" if pressure_val is not None else "UNKNOWN"

    valve_val = state.get("valve_closed")
    valve_str = "CLOSED" if valve_val is True else ("OPEN" if valve_val is False else "UNKNOWN")

    max_press = (
        int(config.REACTOR_PRESSURE_MAX_KPA)
        if isinstance(config.REACTOR_PRESSURE_MAX_KPA, float)
        and config.REACTOR_PRESSURE_MAX_KPA.is_integer()
        else config.REACTOR_PRESSURE_MAX_KPA
    )

    r001_condition_met = (
        pressure_val is not None
        and pressure_val > config.REACTOR_PRESSURE_MAX_KPA
        and valve_val is True
    )

    if r001_condition_met:
        readiness = (
            f"{typer.style('R001 condition MET', fg=typer.colors.RED, bold=True)} "
            f"(pressure>{max_press} AND valve closed)"
        )
    else:
        readiness = (
            f"{typer.style('R001 condition NOT met', fg=typer.colors.GREEN)} "
            f"(need pressure>{max_press} AND valve closed)"
        )

    return f"[{ts}] pressure {press_str}/{max_press} kPa | valve {valve_str} -> {readiness}"


@app.command()
def monitor(
    interface: str = typer.Option(
        None, "--interface", "-i", help="Network interface to sniff packets on (e.g. eth0, wlan0)"
    ),
    remote: bool = typer.Option(
        False,
        "--remote",
        "-r",
        help="Enable remote capture via SSH jump chain as configured in config.py",
    ),
    verbose: bool = typer.Option(
        False,
        "--verbose",
        "-v",
        help="Enable verbose output (logs all normal Modbus traffic as well)",
    ),
    save_pcap: str = typer.Option(
        None,
        "--save-pcap",
        help="Save raw captured traffic to a PCAP file (supported for local interface capture)",
    ),
) -> None:
    """Start passive Modbus TCP packet capture and analysis engine."""
    if (interface is None and not remote) or (interface is not None and remote):
        typer.secho(
            "[!] Error: You must provide exactly one of --interface (-i) or --remote (-r).",
            fg=typer.colors.RED,
            bold=True,
        )
        raise typer.Exit(code=1)

    if save_pcap and remote:
        typer.secho(
            "[!] Notice: --save-pcap is supported for local interface capture only.",
            fg=typer.colors.YELLOW,
        )

    typer.secho("[*] Initializing GridWatch Passive Monitor...", fg=typer.colors.CYAN, bold=True)
    typer.echo(f"[*] Subnet Config: ICS={config.ICS_SUBNET_STR}, DMZ={config.DMZ_SUBNET_STR}")
    if remote:
        typer.echo("[*] Monitoring mode: REMOTE (SSH Jump Chain)")
    else:
        typer.echo(f"[*] Monitoring interface: {interface}")
    typer.echo(f"[*] Verbose logging: {'ENABLED' if verbose else 'DISABLED'}")
    if save_pcap and not remote:
        typer.echo(f"[*] Saving capture to PCAP: {save_pcap}")
    typer.secho(
        "[+] Sniffing Modbus TCP traffic (Port 502)... Press Ctrl+C to stop.",
        fg=typer.colors.GREEN,
        bold=True,
    )

    logger = setup_logging()

    state: PacketData = {"reactor_pressure": None, "valve_closed": None}

    def packet_callback(parsed_packet: PacketData) -> None:
        print_parsed_packet(parsed_packet)

        if verbose:
            logger.info(json.dumps(build_traffic_log_entry(parsed_packet)))

        alerts = process_packet(parsed_packet, state, emit_azure=True)
        for alert in alerts:
            print_alert(alert)

            logger.info(json.dumps(build_alert_log_entry(alert)))

    if remote:
        parser = RemoteModbusCapture()
        try:
            parser.start_capture(callback=packet_callback)
        except KeyboardInterrupt:
            typer.secho("\n[-] Monitor stopped by user.", fg=typer.colors.YELLOW, bold=True)
        except Exception as exc:
            typer.secho(f"\n[!] Error during packet capture: {exc}", fg=typer.colors.RED, bold=True)
            raise typer.Exit(code=1) from exc
    else:
        parser = ModbusParser(interface=interface)
        try:
            parser.start_capture(callback=packet_callback, output_file=save_pcap)
        except KeyboardInterrupt:
            typer.secho("\n[-] Monitor stopped by user.", fg=typer.colors.YELLOW, bold=True)
        except Exception as exc:
            typer.secho(f"\n[!] Error during packet capture: {exc}", fg=typer.colors.RED, bold=True)
            raise typer.Exit(code=1) from exc


@app.command()
def watch(
    interface: str = typer.Option(
        None, "--interface", "-i", help="Network interface to sniff packets on (e.g. eth0, wlan0)"
    ),
    remote: bool = typer.Option(
        False,
        "--remote",
        "-r",
        help="Enable remote capture via SSH jump chain as configured in config.py",
    ),
) -> None:
    """Live read-only state watcher for Modbus IR100 (valve) and IR108 (pressure) registers."""
    if (interface is None and not remote) or (interface is not None and remote):
        typer.secho(
            "[!] Error: You must provide exactly one of --interface (-i) or --remote (-r).",
            fg=typer.colors.RED,
            bold=True,
        )
        raise typer.Exit(code=1)

    typer.secho(
        "[*] Initializing GridWatch Live State Watcher (Read-Only)...",
        fg=typer.colors.CYAN,
        bold=True,
    )
    if remote:
        typer.echo("[*] Monitoring mode: REMOTE (SSH Jump Chain)")
    else:
        typer.echo(f"[*] Monitoring interface: {interface}")
    typer.secho(
        "[+] Watching IR100 (valve) & IR108 (pressure) state... Press Ctrl+C to stop.",
        fg=typer.colors.GREEN,
        bold=True,
    )

    state: PacketData = {"reactor_pressure": None, "valve_closed": None}
    watch_dedup = AlertDeduplicator()

    def packet_callback(parsed_packet: PacketData) -> None:
        process_packet(parsed_packet, state, emit_azure=False, deduplicator=watch_dedup)

        packet_regs = parsed_packet.get("registers", {})
        ref_num = parsed_packet.get("ref_num")

        touches_valve = (config.REG_VALVE_STATE in packet_regs) or (
            ref_num == config.REG_VALVE_STATE
        )
        touches_pressure = (config.REG_REACTOR_PRESSURE in packet_regs) or (
            ref_num == config.REG_REACTOR_PRESSURE
        )

        if touches_valve or touches_pressure:
            line = format_watch_state_line(parsed_packet, state)
            typer.echo(line)

    if remote:
        parser = RemoteModbusCapture()
    else:
        parser = ModbusParser(interface=interface)

    try:
        parser.start_capture(callback=packet_callback)
    except KeyboardInterrupt:
        typer.secho("\n[-] Watcher stopped by user.", fg=typer.colors.YELLOW, bold=True)
    except Exception as exc:
        typer.secho(f"\n[!] Error during state watch: {exc}", fg=typer.colors.RED, bold=True)
        raise typer.Exit(code=1) from exc


@app.command()
def replay(
    pcap: str = typer.Option(..., "--pcap", "-p", help="Path to PCAP file to replay"),
    azure: bool = typer.Option(
        False,
        "--azure/--no-azure",
        help="Upload triggered alerts to Azure Blob Storage (defaults to OFF)",
    ),
) -> None:
    """Replay saved PCAP network captures through GridWatch rules engine (Read-Only by default)."""
    if not os.path.isfile(pcap):
        typer.secho(f"[!] Error: PCAP file not found: '{pcap}'", fg=typer.colors.RED, bold=True)
        raise typer.Exit(code=1)

    typer.secho(
        f"[*] Initializing GridWatch PCAP Replay for '{pcap}'...",
        fg=typer.colors.CYAN,
        bold=True,
    )
    typer.echo(f"[*] Azure Alert Upload: {'ENABLED' if azure else 'DISABLED (Default)'}")

    parser = ModbusParser(interface="")
    replay_dedup = AlertDeduplicator()
    state: PacketData = {"reactor_pressure": None, "valve_closed": None}

    total_packets = 0
    rule_counts: dict[str, int] = {"R001": 0, "R002": 0, "R003": 0, "R004": 0}

    capture = None
    try:
        capture = pyshark.FileCapture(pcap, display_filter=f"tcp port {config.MODBUS_PORT}")
        for raw_packet in capture:
            try:
                parsed = parser.parse_packet(raw_packet)
                if parsed:
                    total_packets += 1
                    alerts = process_packet(
                        parsed, state, emit_azure=azure, deduplicator=replay_dedup
                    )
                    for alert in alerts:
                        print_alert(alert)
                        rule_id = alert.get("rule_id")
                        if rule_id in rule_counts:
                            rule_counts[rule_id] += 1
            except Exception as pkt_err:
                logger.debug(f"Skipping malformed packet during replay: {pkt_err}")
    except Exception as err:
        typer.secho(
            f"[!] Error: Failed to read or parse PCAP file '{pcap}': {err}",
            fg=typer.colors.RED,
            bold=True,
        )
        raise typer.Exit(code=1) from None
    finally:
        if capture is not None:
            try:
                capture.close()
            except Exception:
                pass

    typer.secho("\n[*] PCAP Replay Completed.", fg=typer.colors.GREEN, bold=True)
    typer.echo(f"[*] Total Packets Processed: {total_packets}")
    typer.echo(
        f"[*] Alert Summary: R001: {rule_counts['R001']} | "
        f"R002: {rule_counts['R002']} | "
        f"R003: {rule_counts['R003']} | "
        f"R004: {rule_counts['R004']}"
    )


if __name__ == "__main__":
    app()
