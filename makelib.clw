
  Program

OMIT('***')
 * Copyright (c) 2022 Dylan Giles
 *
 * Created with Clarion 11.0
 * Date: 21/10/2022
 * Time: 9:54 AM
 ***

  Map
      ReadExecutable()
      DumpPEExportTable(ULong VirtualAddress, ULong ImageBase)
      WriteLib()
  End
  
  
Clip      String(255)        ! File name for input and output files
  
Library   File, Driver('DOS','/FILEBUFFERS=20'), Pre(LIB), Create, Name(Clip)
Record        Record
RawBytes          Byte, Dim(1024)
header            Group, Over(RawBytes)
typ                   Byte         ! OMF record type = 88H (Coment)
Len                   UShort        ! Size of OMF record to follow
kind                  UShort        ! Comment kind = 0A000H
bla                   Byte         ! Always 1 for our purposes
ordflag               Byte         ! ditto
                  End

! For the records we want, the header is follower by the pubname
! and modname in PString format, Then the ordinal export number (UShort)
pStringval        PString(128), Over(RawBytes)
UShortval         UShort, Over(RawBytes)
              End
          End
      

TxtFile   File, Pre(Txt), Driver('ASCII','/FILEBUFFERS=20'), Create, Name(Clip)
Record        Record
Line              String(256)
              End
          End

! ExecutableFile is used for reading NE and PE format executable files
ExecutableFile  File, Driver('DOS','/FILEBUFFERS=20'), Pre(EXE), Name(Clip)
Record              Record
RawBytes                Byte, Dim(1024)
cStringval              CString(128), Over(RawBytes)
pStringval              PString(128), Over(RawBytes)
ULongval                ULong, Over(RawBytes)
UShortval               UShort, Over(RawBytes)

! DOSheader is the old exe (stub) header format
DOSheader               Group, Over(RawBytes)
dos_magic                   String(2)      ! contains 'MZ'
dos_filler                  UShort, Dim(29)   ! we don't care about these fields
dos_lfanew                  ULong         ! File offset of new exe header
                        End

! NEheader is the new exe (16-bit) header format
NEheader                Group, Over(RawBytes)
ne_magic                    String(2)      ! Contains 'NE'
ne_ver                      Byte
ne_rev                      Byte
ne_enttab                   UShort
ne_cbenttab                 UShort
ne_crc                      Long
ne_flags                    UShort
ne_autodata                 UShort
ne_heap                     UShort
ne_stack                    UShort
ne_csip                     ULong
ne_sssp                     ULong
ne_cseg                     UShort
ne_cmod                     UShort
ne_cbnrestab                UShort
ne_segtab                   UShort
ne_rsrctab                  UShort
ne_restab                   UShort
ne_modtab                   UShort
ne_imptab                   UShort
ne_nrestab                  ULong
ne_cmovent                  UShort
ne_align                    UShort
ne_rescount                 UShort
ne_osys                     Byte
ne_flagsother               Byte
ne_gangstart                UShort
ne_gangLength               UShort
ne_swaparea                 UShort
ne_expver                   UShort        ! Expected Window version number
                        End

! PEheader is the flat-model (32-bit) header format (PE signature)
PEheader                Group, Over(RawBytes)
pe_signature                ULong
pe_machine                  UShort
pe_nsect                    UShort
pe_stamp                    ULong
pe_psymbol                  ULong
pe_nsymbol                  ULong
pe_optSize                  UShort
pe_character                UShort
                        End

! Optheader is the "optional header" that follows the PEheader

OptHeader               Group, Over(RawBytes)
opt_Magic                   UShort
opt_MajorLinkerVer          Byte
opt_MinorLinkerVer          Byte
opt_SizeOfCode              ULong
opt_SizeOfInitData          ULong
opt_SizeOfUninit            ULong
opt_EntryPoint              ULong
opt_BaseOfCode              ULong
opt_BaseOfData              ULong
opt_ImageBase               ULong
opt_SectAlignment           ULong
opt_FileAlignment           ULong
opt_MajorOSVer              UShort
opt_MinorOSVer              UShort
opt_MajorImageVer           UShort
opt_MinorImageVer           UShort
opt_MajorSubVer             UShort
opt_MinorSubVer             UShort
opt_Reserved1               ULong
opt_SizeOfImage             ULong
opt_SizeOfHeaders           ULong
opt_CheckSum                ULong
opt_Subsystem               UShort
opt_DllChar                 UShort
opt_StackReserve            ULong
opt_StackCommit             ULong
opt_HeapReserve             ULong
opt_HeapCommit              ULong
opt_LoaderFlags             ULong
opt_DataDirNum              ULong
                        End

! The Optional header is followed by an array of the following structures

DataDir                 Group, Over(RawBytes)
data_VirtualAddr            ULong
data_Size                   ULong
                        End

! SectHeader describes a section in a PE file
SectHeader              Group, Over(RawBytes)
sh_SectName                 CString(8)
sh_VirtSize                 ULong
sh_PhysAddr                 ULong, Over(sh_VirtSize)
sh_VirtAddr                 ULong
sh_RawSize                  ULong
sh_RawPtr                   ULong
sh_Reloc                    ULong
sh_LineNum                  ULong
sh_RelCount                 UShort
sh_LineCount                UShort
sh_Character                ULong
                        End

! ExpDirectory is at start of a .edata section in a PE file
ExpDirectory            Group, Over(RawBytes)
exp_Character               ULong
exp_stamp                   ULong
exp_Major                   UShort
exp_Minor                   UShort
exp_Name                    ULong
exp_Base                    ULong
exp_NumFuncs                ULong
exp_NumNames                ULong
exp_AddrFuncs               ULong
exp_AddrNames               ULong
exp_AddrOrds                ULong
                        End
                    End
                End

newoffset       ULong  ! File offset to NE/PE header

ExportQ         Queue, Pre(EXQ)
Symbol              CString(129)
icon                Short
treelevel           Short
ordinal             UShort
module              CString(21)
libno               UShort
                End
                
LastLib         UShort(0)
  Code
  If Command('IN') = '' Or Command('OUT') = '' Then
      SetExitCode(-1)
      Halt(-1)
  End
  
  ExecutableFile{PROP:Name} = Command('IN')
  Library{PROP:Name} = Command('OUT')
  
  ReadExecutable()
  WriteLib()


!!! <summary>
!!! Gets the export table from 16 or 32-bit file or LIB file
!!! </summary>
ReadExecutable  Procedure
sectheaders     ULong   ! File offset to section headers
sections        UShort  ! File offset to section headers
VAexport        ULong   ! Virtual Address of export table, according to data directory

! This is used as an alternative way to find table If .edata not found
  Code
  Open(ExecutableFile, 0)
  Get(ExecutableFile, 1, Size(EXE:DOSheader))
  If EXE:dos_magic = 'MZ' Then
      newoffset = EXE:dos_lfanew
      Get(ExecutableFile, newoffset+1, Size(EXE:PEheader))

      If EXE:pe_signature = 04550H Then
          sectheaders = EXE:pe_optSize+newoffset+Size(EXE:PEheader)
          sections = EXE:pe_nsect
          
          ! Read the "Optional header"
          Get(ExecutableFile, newoffset + Size(EXE:PEheader) + 1, Size(EXE:Optheader))
          If EXE:opt_DataDirNum Then
              
              ! First data directory describes where to find export table
              Get(ExecutableFile, newoffset + Size(EXE:PEheader) + Size(EXE:OptHeader) + 1, Size(EXE:DataDir))
              VAexport = EXE:data_VirtualAddr
          End

          Loop i# = 1 To sections
              Get(ExecutableFile,sectheaders + 1, Size(EXE:sectheader))
              sectheaders += Size(EXE:sectheader)
              
              If EXE:sh_SectName = '.edata' Then
                  DumpPEExportTable(EXE:sh_VirtAddr, EXE:sh_VirtAddr - EXE:sh_rawptr)
              ElsIf EXE:sh_VirtAddr <= VAexport AND EXE:sh_VirtAddr+EXE:sh_RawSize > VAexport Then
                  DumpPEExportTable(VAexport, EXE:sh_VirtAddr - EXE:sh_rawptr)
              End
          End
      Else
          Get(ExecutableFile, newoffset + 1, Size(EXE:NEheader))
          ! DumpNEExports()
      End
  End
  Close(ExecutableFile)

!!! <summary>
!!! Gets export table from a PE format file (32-bit)
!!! <param name="VirtualAddress">The virtual address of the image, received from its PE header.</param>
!!! <param name="ImageBase">The base offset that the image has, received from its PE header.</param>
!!! </summary>
DumpPEExportTable   Procedure(ULong VirtualAddress, ULong ImageBase)
NumNames  ULong, Auto
Names     ULong, Auto
Ordinals  ULong, Auto
Base      ULong, Auto
j         Unsigned, Auto

  Code
  Get(ExecutableFile, VirtualAddress-ImageBase + 1, Size(EXE:ExpDirectory))
  NumNames  = EXE:exp_NumNames
  Names     = EXE:exp_AddrNames
  Ordinals  = EXE:exp_AddrOrds
  Base      = EXE:exp_Base
  
  Get(ExecutableFile, EXE:exp_Name - ImageBase + 1, Size(EXE:cStringval))

  ExportQ.Module    = EXE:cStringval
  ExportQ.Symbol    = EXE:cStringval
  ExportQ.TreeLevel = 1
  ExportQ.Icon      = 1
  ExportQ.Ordinal   = 0
  ExportQ.Libno     = LastLib
  Add(ExportQ)

  ExportQ.TreeLevel = 2
  ExportQ.Icon    = 0

  Loop j = 0 To NumNames - 1
      Get(ExecutableFile, Names + j * 4 - ImageBase + 1, Size(EXE:ULongval))
      Get(ExecutableFile, EXE:ULongval - ImageBase + 1, Size(EXE:cStringval))
      ExportQ.Symbol = EXE:cStringval
  
      Get(ExecutableFile, Ordinals + j * 2 - ImageBase + 1, Size(EXE:UShortval))
      ExportQ.Ordinal = EXE:UShortval+Base
      ExportQ.Libno = LastLib + 1
      Add(ExportQ)
  End
  
!!! <summary>
!!! Writes out all info in the export queue to a LIB file.
!!! </summary>
WriteLib  Procedure
rec    Unsigned, Auto
  Code
  Create(Library)
  Open(Library)
  Loop rec = 1 TO RECORDS(ExportQ)
      Get(ExportQ, rec)
      If ExportQ.TreeLevel = 2 Then
          ! Record Size is Length of the Strings, plus two Length Bytes, a two Byte
          ! ordinal, plus the header Length (excluding the first three Bytes)
          LIB:typ = 88H
          LIB:kind = 0A000H
          LIB:bla = 1
          LIB:ordflag = 1
          LIB:Len = Len(Clip(exq:module)) + Len(Clip(exq:Symbol)) + 2 + 2 + Size(LIB:header)- 3
          Add(Library, Size(LIB:header))
          LIB:pStringval = ExportQ.Symbol
          Add(Library, Len(LIB:pStringval) + 1)
          LIB:pStringval = ExportQ.Module
          Add(Library, Len(LIB:pStringval) + 1)
          LIB:UShortval = ExportQ.Ordinal
          Add(Library, Size(LIB:UShortval))
      End
  End
  Close(Library)
