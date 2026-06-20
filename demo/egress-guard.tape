# VHS tape for the cross-provider egress guard demo.
# Render with:  vhs demo/egress-guard.tape   (produces demo/egress-guard.gif)
# https://github.com/charmbracelet/vhs
Output demo/egress-guard.gif

Set Shell bash
Set FontSize 13
Set Width 1320
Set Height 1080
Set Padding 20
Set TypingSpeed 30ms

Hide
Type "clear"
Enter
Show

Type "bash demo/demo.sh"
Sleep 600ms
Enter
Sleep 7s
