
Esc::ExitApp
F3::GatherSamples("test")
F4::GatherSamples("risc")

GatherSamples(Mode) {
	Counter := 0
	Loop, 100 {
		CoordMode, Mouse
		Click, 642, 70

		MouseMove, 1500, 70
		WinActivate, miniterm.py
		Send %Mode%`n

		WinActivate, Hantek6022BE
		Send ^s
		Sleep 100
		Send `n
		Sleep 250
		Send %Mode%%Counter%`n

		Counter := Counter + 1
	}
	return
}        

