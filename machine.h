// machine.h
#pragma once
#include <stdint.h>

// This struct defines the "contract" between
// the Z80 core and any machine we want to emulate.
typedef struct {
    // Function to read a byte from a memory address
    uint8_t (*mem_read)(uint16_t address);
    
    // Function to write a byte to a memory address
    void (*mem_write)(uint16_t address, uint8_t value);
    
    // Function to read a byte from an I/O port
    uint8_t (*io_read)(uint16_t port);
    
    // Function to write a byte to an I/O port
    void (*io_write)(uint16_t port, uint8_t value);

    // You can also add a function for timing/sync
    // void (*run_machine_cycles)(int cpu_tstates);

} Machine;

// A global or passed-in pointer to the currently running machine
extern Machine* current_machine;
