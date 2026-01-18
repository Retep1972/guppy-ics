from pathlib import Path
from guppy_ics.web.deps import templates
from guppy_ics.analysis.run import analyze_pcap

CALIBRATION_PCAP = (
    Path(__file__).resolve().parents[1]
    / "calibration_data"
    / "MODBUS-TestDATAPart1.pcap"
)


def run_modbus_calibration():
    """
    Run the built-in Modbus calibration PCAP.
    Returns AnalysisState.
    """
    if not CALIBRATION_PCAP.exists():
        raise FileNotFoundError(f"Calibration PCAP not found: {CALIBRATION_PCAP}")

    return analyze_pcap(
        str(CALIBRATION_PCAP),
        enabled_protocols=["modbus"],
    )
