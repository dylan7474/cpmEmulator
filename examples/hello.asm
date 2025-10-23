; Simple CP/M-compatible test program for the emulator.
; Assemble to run at 0x0100 (the transient program area).
; Displays a greeting through BDOS function 9 then exits.

            org     0x0100

start:      lxi     d, message     ; BDOS expects DE to point at the string
            mvi     c, 9           ; BDOS function 9: print "$"-terminated string
            call    0x0005         ; BDOS entry point

            mvi     c, 0           ; BDOS function 0: warm boot / terminate
            call    0x0005

message:    db      'Hello from CP/M!', 13, 10, '$'
