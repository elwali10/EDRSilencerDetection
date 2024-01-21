import "pe"
rule edr_silencer_hacktool {
    meta:
        author = "Subhash Popuri <@pbssubhash> & Elwali Karkoub <@ElwaliKarkoub>"
        filetype = "Executable"
        description = "Detects EDR Silencer tool, that's used to essentially suppress communication between EDR agent and it's server"
        date = "01/21/2024"
        version = "1.1"
    strings:
        $a1 = "SeDebugPrivilege" fullword ascii 
        $a2 = "FwpmEngineClose0" fullword ascii
        $a3 = "FwpmEngineOpen0" fullword ascii
	$edr1 = "MsMpEng.exe" fullword ascii
	$edr2 = "MsSense.exe" fullword ascii
	$edr3 = "SenseIR.exe" fullword ascii
	$edr4 = "SenseNdr.exe" fullword ascii
	$edr5 = "SenseSampleUploader.exe" fullword ascii
	$edr6 = "SenseCncProxy.exe" fullword ascii
	$edr7 = "elastic-agent.exe" fullword ascii
	$edr8 = "elastic-endpoint.exe" fullword ascii
        $edr9 = "wazuh-agent.exe" fullword ascii
        $edr10 = "winlogbeat.exe" fullword ascii
	$edr11 = "filebeat.exe" fullword ascii
	$edr12 = "xagt.exe" fullword ascii
	$edr13 = "QualysAgent.exe" fullword ascii
        $edr14 = "SentinelAgent.exe" fullword ascii
        $edr15 = "SentinelAgentWorker.exe" fullword ascii
        $edr16 = "SentinelServiceHost.exe" fullword ascii
    	$edr17 = "SentinelStaticEngine.exe" fullword ascii
	$edr18 = "LogProcessorService.exe" fullword ascii
	$edr19 = "SentinelStaticEngineScanner.exe" fullword ascii
        $edr20 = "SentinelHelperService.exe" fullword ascii
        $edr21 = "SentinelBrowserNativeHost.exe" fullword ascii
	$edr22 = "CylanceSvc.exe" fullword ascii
	$edr23 = "AmSvc.exe" fullword ascii
	$edr24 = "CrAmTray.exe" fullword ascii
        $edr25 = "CrsSvc.exe" fullword ascii
        $edr26 = "CybereasonAV.exe" fullword ascii
        $edr27 = "cb.exe" fullword ascii
	$edr28 = "RepMgr.exe" fullword ascii
	$edr29 = "RepUtils.exe" fullword ascii
	$edr30 = "RepUx.exe" fullword ascii
        $edr31 = "RepWAV.exe" fullword ascii
        $edr32 = "RepWSC.exe" fullword ascii
        $edr33 = "TaniumClient.exe" fullword ascii
	$edr34 = "TaniumCX.exe" fullword ascii
	$edr35 = "TaniumDetectEngine.exe" fullword ascii
	$edr36 = "Traps.exe" fullword ascii
        $edr37 = "cyserver.exe" fullword ascii
        $edr38 = "CyveraService.exe" fullword ascii
        $edr39 = "CyvrFsFlt.exe" fullword ascii
    	$edr40 = "fortiedr.exe" fullword ascii
	$edr41 = "sfc.exe" fullword ascii
    condition:
        pe.is_pe and all of ($a*) and any of ($edr*)
}
