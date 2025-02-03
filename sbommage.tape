Output "sbommage.gif"
Require syft
Require bash
Require figlet
Set Shell "bash"
Set FontFamily "Iosevka Term"
Set FontSize 14
Set Width 800
Set Height 600
Set Padding 4
Set WindowBar Colorful
#Set WindowBar Rings
Set Theme catppuccin-macchiato
Set Margin 8
Set MarginFill "#0f40c0"
Set BorderRadius 10
Set Framerate 60
Set PlaybackSpeed 1
Env PS1 "[0;38;5;231;48;5;31;1m popey [0;38;5;31;48;5;240;22m [0;38;5;252;48;5;240;1m~ [0;38;5;240;49;22m [0m"
Sleep 50ms
Type `figlet sbommage`
Enter
Sleep 500ms
Type@5ms `./sbommage ./example_sboms/nextcloud-latest-syft-sbom.json`
Sleep 250ms
Enter
Enter
Sleep 500ms
Down
Sleep 50ms
Enter
Sleep 50ms
Down
Sleep 50ms
Enter
Sleep 500ms
Down
Sleep 50ms
Enter
Sleep 500ms
Down
Enter
Sleep 500ms
Down 13
Sleep 50ms
Enter
Sleep 500ms
Type "t"
Sleep 500ms
Enter
Sleep 500ms
Down 2
Sleep 500ms
Enter
Sleep 500ms
Down 2
Sleep 500ms
Enter
Sleep 500ms
Down 4
Enter
Sleep 500ms
Type "c"
Sleep 500ms
Enter
Sleep 500ms
Down 11
Enter
Sleep 500ms
Down
Enter
Sleep 2s
Screenshot sbommage.png
Sleep 1s
Type "q"
Sleep 1s
