"""
Modbus TCP packet parser module.

Uses pyshark to perform passive capture and parse fields from Modbus TCP packets.
Tracks and correlates Modbus transactions to map read response values back to the
register addresses requested earlier in the exchange.
"""

import asyncio
import logging
import subprocess
from collections.abc import Callable
from datetime import datetime

import pyshark

try:
    from gridwatch import config
except ImportError:
    import config


logger = logging.getLogger(__name__)


class ModbusParser:
    def __init__(self, interface: str):
        """Initialize the Modbus parser with the target network interface."""
        self.interface = interface
        self.transaction_map: dict[int, dict[str, int | str | None]] = {}

    @staticmethod
    def _extract_register_values(packet) -> list[int]:
        """Return decoded register values from the Modbus layer when present."""
        if not hasattr(packet.modbus, "regval_uint16"):
            return []

        try:
            fields = packet.modbus.regval_uint16.all_fields
        except AttributeError:
            fields = [packet.modbus.regval_uint16]

        values: list[int] = []
        for field in fields:
            for candidate in (getattr(field, "raw_value", None), getattr(field, "show", None)):
                if candidate is None:
                    continue
                try:
                    values.append(int(candidate, 16))
                    break
                except (ValueError, TypeError):
                    try:
                        values.append(int(candidate))
                        break
                    except (ValueError, TypeError):
                        continue
        return values

    def parse_packet(self, packet) -> dict | None:
        """Extract Modbus TCP fields from a captured packet, correlating read responses with
        requests using transaction IDs.
        """
        if "mbtcp" not in packet or "modbus" not in packet:
            return None

        if not hasattr(packet, "ip"):
            return None

        src_ip = packet.ip.src
        dst_ip = packet.ip.dst

        try:
            trans_id = int(packet.mbtcp.trans_id)
            func_code = int(packet.modbus.func_code)
        except (AttributeError, ValueError):
            return None

        direction = "unknown"
        if hasattr(packet, "tcp"):
            if packet.tcp.dstport == str(config.MODBUS_PORT):
                direction = "request"
            elif packet.tcp.srcport == str(config.MODBUS_PORT):
                direction = "response"

        ref_num = None
        registers: dict[int, int] = {}
        values = self._extract_register_values(packet)

        if direction == "request":
            if hasattr(packet.modbus, "reference_num"):
                try:
                    ref_num = int(packet.modbus.reference_num)
                except ValueError:
                    pass

            if func_code in (3, 4):
                try:
                    word_cnt = int(packet.modbus.word_cnt)
                except (AttributeError, ValueError):
                    word_cnt = 1
                self.transaction_map[trans_id] = {
                    "func_code": func_code,
                    "ref_num": ref_num,
                    "word_cnt": word_cnt,
                    "src_ip": src_ip,
                    "dst_ip": dst_ip,
                }
            elif func_code in (6, 16) and ref_num is not None and values:
                for index, value in enumerate(values):
                    registers[ref_num + index] = value

        elif direction == "response":
            request_info = self.transaction_map.pop(trans_id, None)
            if request_info:
                ref_num = request_info.get("ref_num")
                if ref_num is not None and values:
                    for index, value in enumerate(values):
                        registers[ref_num + index] = value

        sniff_time = getattr(packet, "sniff_time", None) or datetime.now()

        return {
            "timestamp": sniff_time,
            "src_ip": src_ip,
            "dst_ip": dst_ip,
            "trans_id": trans_id,
            "direction": direction,
            "func_code": func_code,
            "ref_num": ref_num,
            "registers": registers,
            "values": values,
        }

    def start_capture(self, callback: Callable[[dict], None]) -> None:
        """Begin capturing Modbus traffic locally, invoking callback on each parsed Modbus
        packet.
        """
        try:
            asyncio.get_event_loop()
        except RuntimeError:
            asyncio.set_event_loop(asyncio.new_event_loop())

        capture = pyshark.LiveCapture(
            interface=self.interface,
            bpf_filter=f"tcp port {config.MODBUS_PORT}",
        )

        for packet in capture.sniff_continuously():
            try:
                parsed = self.parse_packet(packet)
                if parsed:
                    callback(parsed)
            except Exception:
                logger.exception("Failed to parse captured packet; continuing capture loop.")


class RemoteModbusCapture:
    def __init__(self):
        """Initialize the remote Modbus capture using configured SSH jump chain parameters."""
        self.transaction_map: dict[int, dict[str, int | str | None]] = {}
        self.raw_lines_printed = 0

    def parse_line(self, line: str) -> dict | None:
        """Parse a single CSV line from tshark stdout using index mappings for Modbus fields."""
        # Field mapping: 0=src_ip, 1=dst_ip, 2=src_port, 3=dst_port, 4=trans_id,
        # 5=func_code, 6=ref_num, 7=word_cnt, 8:-1=reg_values, -1=time_epoch
        parts = line.split(",")
        if len(parts) < 10:
            return None

        # Verify it's a Modbus packet by checking trans_id and func_code presence
        trans_id_str = parts[4].strip()
        func_code_str = parts[5].strip()
        if not trans_id_str or not func_code_str:
            return None

        try:
            trans_id = int(trans_id_str)
            func_code = int(func_code_str)
        except ValueError:
            return None

        src_ip = parts[0].strip()
        dst_ip = parts[1].strip()
        src_port_str = parts[2].strip()
        dst_port_str = parts[3].strip()

        direction = "unknown"
        if dst_port_str == str(config.MODBUS_PORT):
            direction = "request"
        elif src_port_str == str(config.MODBUS_PORT):
            direction = "response"

        # Extract values
        values_raw = parts[8:-1]
        values = []
        for val in values_raw:
            val = val.strip()
            if val:
                # Handle potential list or hex strings
                try:
                    if val.lower().startswith("0x"):
                        values.append(int(val, 16))
                    else:
                        values.append(int(val))
                except ValueError:
                    try:
                        values.append(int(val, 16))
                    except ValueError:
                        pass

        ref_num = None
        registers: dict[int, int] = {}

        if direction == "request":
            ref_num_str = parts[6].strip()
            if ref_num_str:
                try:
                    ref_num = int(ref_num_str)
                except ValueError:
                    pass

            if func_code in (3, 4):
                word_cnt_str = parts[7].strip()
                try:
                    word_cnt = int(word_cnt_str) if word_cnt_str else 1
                except ValueError:
                    word_cnt = 1
                self.transaction_map[trans_id] = {
                    "func_code": func_code,
                    "ref_num": ref_num,
                    "word_cnt": word_cnt,
                    "src_ip": src_ip,
                    "dst_ip": dst_ip,
                }
            elif func_code in (6, 16) and ref_num is not None and values:
                for index, value in enumerate(values):
                    registers[ref_num + index] = value

        elif direction == "response":
            request_info = self.transaction_map.pop(trans_id, None)
            if request_info:
                ref_num = request_info.get("ref_num")
                if ref_num is not None and values:
                    for index, value in enumerate(values):
                        registers[ref_num + index] = value

        # Parse epoch time
        try:
            timestamp = datetime.fromtimestamp(float(parts[-1].strip()))
        except (ValueError, TypeError):
            timestamp = datetime.now()

        return {
            "timestamp": timestamp,
            "src_ip": src_ip,
            "dst_ip": dst_ip,
            "trans_id": trans_id,
            "direction": direction,
            "func_code": func_code,
            "ref_num": ref_num,
            "registers": registers,
            "values": values,
        }

    def start_capture(self, callback: Callable[[dict], None]) -> None:
        """Begin remote capture by chaining SSH and tshark subprocesses, invoking callback on
        each parsed packet line.
        """
        ssh_cmd = [
            "ssh",
            "-J",
            f"{config.JUMP_USER}@{config.LAPTOP_A_IP}",
            f"{config.VM_USER}@{config.VM_IP}",
            f"docker exec {config.CAPTURE_CONTAINER} tcpdump -i "
            f"{config.CONTAINER_CAPTURE_INTERFACE} port 502 -w -",
        ]

        tshark_cmd = [
            "tshark",
            "-i",
            "-",
            "-T",
            "fields",
            "-e",
            "ip.src",
            "-e",
            "ip.dst",
            "-e",
            "tcp.srcport",
            "-e",
            "tcp.dstport",
            "-e",
            "mbtcp.trans_id",
            "-e",
            "modbus.func_code",
            "-e",
            "modbus.reference_num",
            "-e",
            "modbus.word_cnt",
            "-e",
            "modbus.regval_uint16",
            "-e",
            "frame.time_epoch",
            "-E",
            "separator=,",
        ]

        logger.info(f"Starting remote capture: {' '.join(ssh_cmd)} | {' '.join(tshark_cmd)}")

        ssh_proc = None
        tshark_proc = None

        try:
            ssh_proc = subprocess.Popen(
                ssh_cmd,
                stdout=subprocess.PIPE,
            )

            tshark_proc = subprocess.Popen(
                tshark_cmd,
                stdin=ssh_proc.stdout,
                stdout=subprocess.PIPE,
                stderr=subprocess.DEVNULL,
                text=True,
                encoding="utf-8",
                errors="replace",
            )

            # Close our copy of the write end of the pipe
            if ssh_proc.stdout:
                ssh_proc.stdout.close()

            # Read tshark's stdout line by line
            for line in tshark_proc.stdout:
                line_str = line.strip()
                if not line_str:
                    continue

                if self.raw_lines_printed < 5:
                    print(
                        f"[Remote Capture] Raw tshark line {self.raw_lines_printed + 1}: {line_str}"
                    )
                    self.raw_lines_printed += 1

                try:
                    parsed = self.parse_line(line_str)
                    if parsed:
                        callback(parsed)
                except Exception:
                    logger.exception("Failed to parse remote packet line; continuing capture.")

        finally:
            # Clean up processes properly
            for proc in (tshark_proc, ssh_proc):
                if proc is not None:
                    try:
                        if proc.poll() is None:
                            proc.terminate()
                            try:
                                proc.wait(timeout=2)
                            except subprocess.TimeoutExpired:
                                proc.kill()
                                proc.wait()
                    except Exception:
                        pass
