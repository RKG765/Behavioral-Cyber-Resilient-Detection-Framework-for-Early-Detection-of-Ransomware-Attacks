"""
haltline_service.py -- the agent as a Windows service (plan 5.6): LocalSystem, auto-start.

Replaces the "Telltale-Agent" scheduled task in packaged installs. Nuitka builds this file into
haltline-agent.exe; the installer (packaging/haltline.iss) registers it with `sc create`.
Settings come from the service's Environment value (EDR_MODE, EDR_LICENCE_KEY); the endpoints and
keys are baked into edr_sensor by the release build.

    haltline-agent.exe          started by the service control manager
    haltline-agent.exe debug    run in this console (elevated), Ctrl+C to stop
"""
import sys

import pythoncom
import servicemanager
import win32service
import win32serviceutil


class HaltlineService(win32serviceutil.ServiceFramework):
    _svc_name_ = "HaltlineAgent"
    _svc_display_name_ = "Haltline Agent"
    _svc_description_ = "Behavioral ransomware detection: watches new processes and asks before stopping a threat."

    def SvcStop(self):
        self.ReportServiceStatus(win32service.SERVICE_STOP_PENDING)
        import agent
        agent.STOP.set()   # main()'s WMI loop checks it every second

    def SvcDoRun(self):
        pythoncom.CoInitialize()   # WMI is used from this thread
        servicemanager.LogInfoMsg(f"{self._svc_display_name_} starting")
        import agent
        agent.main()
        servicemanager.LogInfoMsg(f"{self._svc_display_name_} stopped")


if __name__ == "__main__":
    if sys.argv[1:] == ["debug"]:
        import agent
        agent.main()
    else:
        servicemanager.Initialize()
        servicemanager.PrepareToHostSingle(HaltlineService)
        servicemanager.StartServiceCtrlDispatcher()
