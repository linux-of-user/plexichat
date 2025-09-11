"""QEMU Manager for PlexiChat infrastructure."""

import asyncio
import json
import os
import subprocess
import typing as t
from pathlib import Path


class QemuManager:
    """Manager for QEMU VM operations."""

    def __init__(self, config_path: str) -> None:
        """Initialize QemuManager with config path."""
        self.config_path = Path(config_path)
        self.configs: t.Dict[str, t.Dict[str, t.Any]] = self._load_configs()

    def _load_configs(self) -> t.Dict[str, t.Dict[str, t.Any]]:
        """Load VM configurations from JSON files."""
        configs = {}
        for config_file in self.config_path.glob("*.json"):
            arch = config_file.stem
            with open(config_file, "r") as f:
                configs[arch] = json.load(f)
        return configs

    async def setup_env(self) -> None:
        """Setup QEMU environment by running installation script."""
        await asyncio.to_thread(self._install_qemu)

    def _install_qemu(self) -> None:
        """Run platform-specific QEMU installation script."""
        scripts_dir = Path(__file__).parent.parent.parent.parent / "scripts" / "qemu"
        if os.name == "nt":  # Windows
            script = scripts_dir / "setup.bat"
            subprocess.run([str(script)], shell=True, check=True)
        else:  # Linux/WSL/macOS
            script = scripts_dir / "setup.sh"
            subprocess.run(["bash", str(script)], check=True)

    async def spin_base_vm(self, arch: str) -> str:
        """Spin up a base VM for the given architecture."""
        if arch not in self.configs:
            raise ValueError(f"Architecture {arch} not found in configs")
        config = self.configs[arch]
        vm_id = await asyncio.to_thread(self._run_qemu, config)
        return vm_id

    def _run_qemu(self, config: t.Dict[str, t.Any]) -> str:
        """Run QEMU with given configuration."""
        arch = config["arch"]
        qemu_cmd = ["qemu-system-" + arch.replace("_", "-")]

        # Add machine type for ARM
        if arch == "aarch64":
            qemu_cmd.extend(["-machine", config.get("machine", "virt")])
            qemu_cmd.extend(["-cpu", config.get("cpu", "cortex-a72")])

        # Add common options
        qemu_cmd.extend([
            "-m", config["memory"],
            "-smp", str(config["cpus"]),
            "-drive", f"file={config['disk']},format=raw",
            "-netdev", config["net"],
            "-device", config["device"],
            "-boot", config["boot"],
            "-cdrom", config["cdrom"]
        ])

        # Enable KVM if on Linux
        if os.name != "nt":
            qemu_cmd.append("-enable-kvm")

        # Run QEMU process
        process = subprocess.Popen(
            qemu_cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True
        )

        # Generate VM ID from PID
        vm_id = f"vm-{process.pid}"
        
        # For now, just wait a bit and return ID
        # In production, this would monitor the process
        try:
            stdout, stderr = process.communicate(timeout=5)
            if stderr:
                print(f"QEMU stderr: {stderr}")
        except subprocess.TimeoutExpired:
            process.kill()
            pass  # VM is running

        return vm_id