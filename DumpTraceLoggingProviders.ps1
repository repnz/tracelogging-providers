#requires -version 5

<#
The things you find on Google searching for specific GUIDs...
Known Keyword friendly names:
"UTC:::CATEGORYDEFINITION.MS.CRITICALDATA":"140737488355328"
"UTC:::CATEGORYDEFINITION.MS.MEASURES":"70368744177664"
"UTC:::CATEGORYDEFINITION.MS.TELEMETRY":"35184372088832"
"UTC:::CATEGORYDEFINITION.MSWLAN.CRITICALDATA":"2147483648"
"UTC:::CATEGORYDEFINITION.MSWLAN.MEASURES":"1073741824"
"UTC:::CATEGORYDEFINITION.MSWLAN.TELEMETRY":"536870912"
"UTC:::CATEGORYDEFINITION.WINEVENT.TELEMETRY":"562949953421312"
Known Provider Group Definitions:
"UTC:::GROUPDEFINITION.MICROSOFT-APPLICATIONINSIGHTS":"0d943590-b235-5bdb-f854-89520f32fc0b"
"UTC:::GROUPDEFINITION.MICROSOFT-APPLICATIONINSIGHTS-DEV":"ba84f32b-8af2-5006-f147-5030cdd7f22d"
"UTC:::GROUPDEFINITION.AI":"0d943590-b235-5bdb-f854-89520f32fc0b"
"UTC:::GROUPDEFINITION.AI-DEV":"ba84f32b-8af2-5006-f147-5030cdd7f22d"
"UTC:::GROUPDEFINITION.ARIA":"780dddc8-18a1-5781-895a-a690464fa89c"
"UTC:::GROUPDEFINITION.DEVCNTR":"1d34c0ff-54c5-516f-9ca2-0e20966588a5"
"UTC:::GROUPDEFINITION.ENG":"207cf9d5-b3e5-5f45-9a58-c1308f9abdda"
"UTC:::GROUPDEFINITION.MICROSOFTTELEMETRY":"4f50731a-89cf-4782-b3e0-dce8c90476ba"
"UTC:::GROUPDEFINITION.MICROSOFTWLANTELEMETRY":"976a8310-986e-4640-8bfb-7736ee6d9b65"
"UTC:::GROUPDEFINITION.MSPG":"5ECB0BAC-B930-47F5-A8A4-E8253529EDB7"
"UTC:::GROUPDEFINITION.OFFICE":"8DBEEE55-EAB8-41BE-988E-B1FAE0397155"
"UTC:::GROUPDEFINITION.SEVILLE":"541dae91-cc3c-5807-b064-c2561c16d7e8"
"UTC:::GROUPDEFINITION.SKYPE":"9dfc8457-4d69-44c7-8fcd-192290702a89"
"UTC:::GROUPDEFINITION.WINDOWSCORETELEMETRY":"c7de053a-0c2e-4a44-91a2-5222ec2ecdf1"
"UTC:::GROUPDEFINITION.XBOX.XSAPI":"53b78fc6-e359-453e-89fe-a5f4e5ff4af3"
#>

# Parsing these out will be useful for grouping by keyword type. e.g. anything not related to telemetry might be more interesting.
# Is CRITICALDATA indicative of sensitive data?
$KeywordMapping = @{
    [UInt64] 140737488355328 = 'MS.CRITICALDATA'
    [UInt64] 70368744177664  = 'MS.MEASURES'
    [UInt64] 35184372088832  = 'MS.TELEMETRY'
    [UInt64] 562949953421312 = 'WINEVENT.TELEMETRY'
}

enum TlgIn {
    NULL = 0
    UNICODESTRING = 1
    ANSISTRING = 2
    INT8 = 3
    UINT8 = 4
    INT16 = 5
    UINT16 = 6
    INT32 = 7
    UINT32 = 8
    INT64 = 9
    UINT64 = 10
    FLOAT = 11
    DOUBLE = 12
    BOOL32 = 13
    BINARY = 14
    GUID = 15
    POINTER_UNSUPPORTED = 16
    FILETIME = 17
    SYSTEMTIME = 18
    SID = 19
    HEXINT32 = 20
    HEXINT64 = 21
    COUNTEDSTRING = 22
    COUNTEDANSISTRING = 23
    STRUCT = 24
    # The following enum values will not be defined since they collide with other types:
    # INTPTR, UINTPTR, POINTER
    # These should have been defined as unique values in TraceLoggingProvider.h
}

enum TlgOut {
    NULL = 0
    NOPRINT = 1
    STRING = 2
    BOOLEAN = 3
    HEX = 4
    PID = 5
    TID = 6
    PORT = 7
    IPV4 = 8
    IPV6 = 9
    SOCKETADDRESS = 10
    XML = 11
    JSON = 12
    WIN32ERROR = 13
    NTSTATUS = 14
    HRESULT = 15
    FILETIME = 16
    SIGNED = 17
    UNSIGNED = 18
    UTF8 = 35
    PKCS7_WITH_TYPE_INFO = 36
    CODE_POINTER = 37
}

class TlgEventField {
    [string] $FieldName
    [string]$InType
    [string]$OutType
    [System.Collections.Generic.List[Byte]]$Extension
    [int]$ValueCount
    [string]$TypeInfo

    TlgEventField(){
        $this.Extension = New-Object 'System.Collections.Generic.List[Byte]'
    }
}

class TlgEvent {
    [int]$EventID
    [int]$Channel
    [int]$Level
    [int]$Opcode
    [Uint64]$Keyword
    [string]$KeywordName
    [System.Collections.Generic.List[Byte]]$Extension
    [string]$EventName
    [System.Collections.Generic.List[TlgEventField]]$Fields

    TlgEvent(){
        $this.Extension = New-Object 'System.Collections.Generic.List[Byte]' 
        $this.Fields = New-Object 'System.Collections.Generic.List[TlgEventField]' 
    }
}


class TlgProvider {
    [string]$ProviderGUID
    [string]$ProviderName
    [string]$ProviderGroupGUID
}

class TlgExecutable {
    [System.Collections.Generic.List[TlgProvider]]$ProviderList
    [System.Collections.Generic.List[TlgEvent]]$EventList
    [string]$FilePath

    TlgExecutable(){
        $this.ProviderList = New-Object 'System.Collections.Generic.List[TlgProvider]'
        $this.EventList = New-Object 'System.Collections.Generic.List[TlgEvent]'
    }
}

function Get-TraceLoggingMetadata {
<#
.SYNOPSIS
Retrieves TraceLogging metadata from a file.
.DESCRIPTION
Get-TraceLoggingMetadata retrieves TraceLogging metadata from a file. TraceLogging is what enables ETW tracing to occur without needing to register/install a manifest. Rather, event metadata is embedded within trace data which Windows 10-based tools are able to parse. Wanting to know what providers and events were possible for a given binary, Get-TraceLoggingMetadata was developed to extract this information. The majority of Get-TraceLoggingMetadata was developed with the assistance of TraceLoggingProvider.h from the Windows SDK.
The intended purpose of Get-TraceLoggingMetadata is for research purposes where you would like to discover whether or not interesting providers/events can be traced for one or more binaries. Once an interesting provider is identified, a trace can be captured with a tool like Windows Problem Recorder (wpr.exe). Once a trace is collected, it can be formatted and parsed properly with tracerpt.exe.
Author: Matthew Graeber (@mattifestation)
License: BSD 3-Clause
.PARAMETER Path
Specifies the path to a file that may contain trace logging metadata.
.EXAMPLE
Get-TraceLoggingMetadata -Path C:\Windows\System32\LocationFramework.dll
Retrieves trace logging metadata from a specific file.
.EXAMPLE
Get-ChildItem -Path 'C:\Program Files\*' -Include '*.dll', '*.exe' -Recurse | Get-TraceLoggingMetadata
Retrieves trace logging metadata for any EXE or DLL within "C:\Program Files\".
.EXAMPLE
(Get-Process -Id $PID).Modules.FileName | Get-ChildItem | Get-TraceLoggingMetadata
Retrieves trace logging metadata for any loaded module within the current PowerShell process.
.INPUTS
System.IO.FileInfo
Accepts one or more files returned from Get-ChildItem.
.OUTPUTS
TraceLogging.Schema
If a file contains trace logging metadata, an object will be output consisting of provider and event information. Get-TraceLoggingMetadata will only output an object if the file actually contains trace logging metadata.
#>

    param (
        [Parameter(Mandatory, ValueFromPipelineByPropertyName, Position = 0)]
        [Alias('FullName')]
        [String]
        $Path
    )

    # Resolve the full path in case a relative path was supplied.
    $FullPath = Resolve-Path -Path $Path

    # This string encoding will ensure a 1-to-1 byte<->char mapping.
    $StringEncoder = [Text.Encoding]::GetEncoding(28591)

    $FileBytes = [IO.File]::ReadAllBytes($FullPath)
    $NewTlgExecutable = New-Object 'TlgExecutable'
    $NewTlgExecutable.FilePath = $Path

    $MemoryStream = New-Object -TypeName IO.MemoryStream -ArgumentList @(,$FileBytes)
    $StreamReader = New-Object IO.StreamReader($MemoryStream, $StringEncoder)

    # Search for the trace logging signature value offset - _TlgSigVal
    # Reading all this string is not needed only to search for 'ETW0'..
    $BinaryString = $StreamReader.ReadToEnd()
    $TlgSigValIndex = $BinaryString.IndexOf('ETW0')

    if ($TlgSigValIndex -ne -1) {
        [Console]::WriteLine("yay")

        # "ETW0" was found. Ensure that it is a part of a _TraceLoggingMetadata_t structure.

        # Jump to the offset of "ETW0"
        $StreamReader.BaseStream.Position = $TlgSigValIndex

        $BinaryReader = New-Object -TypeName IO.BinaryReader -ArgumentList $MemoryStream, $StringEncoder

        $TlgSigVal = [Text.Encoding]::ASCII.GetString($BinaryReader.ReadBytes(4))
        $Size = $BinaryReader.ReadUInt16() # sizeof(_TraceLoggingMetadata_t) - Expected to equal 16
        $Version = $BinaryReader.ReadByte()
        $Flags = $BinaryReader.ReadByte()
        $Magic = $BinaryReader.ReadUInt64() # Expected to equal 0xBB8A052B88040E86 (13513619316402294406) - _TlgMagicVal

        if (($Size -eq 16) -and ($Magic -eq ([UInt64] 13513619316402294406))) {
         
            # The next byte is a metadata blob type
            $BlobType = $BinaryReader.ReadByte()

            while ($BlobType -ne 1) { # _TlgBlobEnd: signals _TraceLoggingMetadataEnd

                switch ($BlobType) {
                    0 { # _TlgBlobNone
                        # This is not documented anywhere but I see it pop up in rare instances.
                        # e.g. C:\Windows\System32\LocationFramework.dll has 8 of these after the metadata header prior to landing at the first event metadata blob.
                    }

                    2 { # _TlgBlobProvider

                        <#
                          This is documented nowhere but this provider type is present in C:\Windows\System32\ortcengine.dll *shrug*
                          I've only seen this so far for the "Microsoft.CRTProvider" provider (https://www.reddit.com/r/cpp/comments/4hoyzr/msvc_mutex_is_slower_than_you_might_expect/)
                          Another reference: https://habr.com/post/281374/
                          The following structure can be inferred based on hex editor/IDA analysis:
                          UINT8 Type; // = _TlgBlobProvider
                          UINT16 RemainingSize; // = sizeof(RemainingSize + ProviderName)
                          char ProviderName[sizeof("providerName")]; // UTF-8 nul-terminated provider name
                          GUID ProviderGroupId;
                        #>

                        $RemainingSize = $BinaryReader.ReadUInt16()

                        $ProviderGroupGUID = $null
                        $ProviderName = $null

                        if ($RemainingSize) {
                            $StrBuilder = New-Object Text.StringBuilder

                            # Build up the provider name string until a null is reached.
                            do {
                                $CharVal = $BinaryReader.ReadChar()
                                $null = $   .Append($CharVal)
                            } while ($CharVal -ne "`0")

                            $ProviderName = $StrBuilder.ToString().TrimEnd("`0")

                            # Report if this is anything other than 19.
                            # I would not expect there to be any other data other than a single provider group GUID
                            $RemainingChunkSize = $BinaryReader.ReadUInt16()

                            if ($RemainingChunkSize -ne 19) {
                                Write-Warning 'Unexpected provider metadata chunk size!'
                            }

                            if ($RemainingChunkSize) {
                                # Refers to ETW_PROVIDER_TRAIT_TYPE in evntcons.h
                                $ProviderAdditionalInfoTypeVal = $BinaryReader.ReadByte()

                                switch ($ProviderAdditionalInfoTypeVal) {
                                    1 { # EtwProviderTraitTypeGroup
                                        $ProviderGroupGUID = ([Guid][Byte[]] $BinaryReader.ReadBytes(16)).Guid
                                    }

                                    2 { # EtwProviderTraitDecodeGuid
                                        # I don't expect to see this so alert if it is encountered
                                        Write-Warning 'EtwProviderTraitDecodeGuid value encountered. Inspect this manually and develop a parser.'
                                    }

                                    default {
                                        Write-Warning 'Unknown provider chunk type value encountered. Inspect this manually and develop a parser.'
                                    }
                                }
                            }
                        }

                        $ProviderMetadata = New-Object TlgProvider
                        $ProviderMetadata.ProviderGuid = $null
                        $ProviderMetadata.ProviderName = $ProviderName
                        $ProviderMetadata.ProviderGroupGUID = $ProviderGroupGUID

                        $NewTlgExecutable.ProviderList.Add($ProviderMetadata)
                    }

                    3 { # _TlgBlobEvent3
                        
                        $NewTlgEvent = New-Object TlgEvent

                        $NewTlgEvent.EventID = $BinaryReader.BaseStream.Position - $TlgSigValIndex

                        $NewTlgEvent.Channel = $BinaryReader.ReadByte() # This _should_ always be 11 (TraceLogging - Event contains provider traits and TraceLogging event metadata.)
                        $NewTlgEvent.Level = $BinaryReader.ReadByte()
                        $NewTlgEvent.Opcode = $BinaryReader.ReadByte()

                        $KeywordVal = $BinaryReader.ReadUInt64()

                        $NewTlgEvent.KeywordName = $KeywordMapping[$KeywordVal]
                        $NewTlgEvent.Keyword = "0x$($KeywordVal.ToString('X16'))"

                        $RemainingSize = $BinaryReader.ReadUInt16()


                        # Non-null remaining size implies that event/field metadata exists.
                        if ($RemainingSize) {

                            # Calculate the end stream position and validate along the way that it hasn't been exceeded.
                            # This is required due to how structure are stored in tightly-packed streams that don't
                            # contain fields about metadata length.
                            $EndPosition = $BinaryReader.BaseStream.Position + $RemainingSize - 2 # 2 - sizeof(RemainingSize)

                            <# What follows is an EventMetadata structure:
                                struct EventMetadata // Variable-length pseudo-structure, byte-aligned, tightly-packed.
                                {
                                    UINT16 Size; // = sizeof(EventMetadata)
                                    UINT8 Extension[]; // 1 or more bytes. Read until you hit a byte with high bit unset.
                                    char Name[]; // UTF-8 nul-terminated event name
                                    FieldMetadata Fields[]; // 0 or more field definitions.
                                };
                            #>

                            if ($BinaryReader.BaseStream.Position -ne $EndPosition) {
                                # Read extension array

                                do {
                                    $ExtensionVal = $BinaryReader.ReadByte()
                                    # To-do: inspect to see if this is ever non-zero. It is currently unclear what these are used for.
                                    $NewTlgEvent.ExtensionList.Add($ExtensionVal)
                                    
                                } while ($ExtensionVal -band 0x80)

                                if ($BinaryReader.BaseStream.Position -ne $EndPosition) {
                                    $StrBuilder = New-Object Text.StringBuilder

                                    # Build up the event name string until a null is reached.
                                    do {
                                        $CharVal = $BinaryReader.ReadChar()
                                        $null = $StrBuilder.Append($CharVal)
                                    } while ($CharVal -ne "`0")

                                    $NewTlgEvent.EventName = $StrBuilder.ToString().TrimEnd("`0")

                                    while ($BinaryReader.BaseStream.Position -lt $EndPosition) {

                                        # Parse out all fields in the event. Fields are optional.
                                        <#
                                        struct FieldMetadata // Variable-length pseudo-structure, byte-aligned, tightly-packed.
                                        {
                                            char Name[]; // UTF-8 nul-terminated field name
                                            UINT8 InType; // Values from the TlgIn enumeration.
                                            UINT8 OutType; // TlgOut enumeration. Only present if (InType & 128) == 128.
                                            UINT8 Extension[]; // Only present if OutType is present and (OutType & 128) == 128. Read until you hit a byte with high bit unset.
                                            UINT16 ValueCount;  // Only present if (InType & CountMask) == Ccount.
                                            UINT16 TypeInfoSize; // Only present if (InType & CountMask) == Custom.
                                            char TypeInfo[TypeInfoSize]; // Only present if (InType & CountMask) == Custom.
                                        };
                                        #>

                                        # Build up the field name string until a null is reached.
                                        $StrBuilder = New-Object Text.StringBuilder

                                        do {
                                            $CharVal = $BinaryReader.ReadChar()
                                            $null = $StrBuilder.Append($CharVal)
                                        } while ($CharVal -ne "`0")

                                        $NewTlgEventField = New-Object 'TlgEventField'

                                        $NewTlgEventField.FieldName = $StrBuilder.ToString().TrimEnd("`0")

                                        $InTypeVal = $BinaryReader.ReadByte()

                                        $InTypeMask = 31

                                        <#
                                        if ($InTypeVal -band 64) {
                                            Write-Warning "VCount Tag Flag Encountered! Current position: 0x$($BinaryReader.BaseStream.Position.ToString('X8'))"
                                        }
                                        #>

                                        $OutTypeVal = $null

                                        if ($InTypeVal -band 128) {
                                            # This means that the OutType field is populated.
                                            $OutTypeVal = $BinaryReader.ReadByte()

                                            $OutTypeMask = 127

                                            if ($OutTypeVal -band 128) {

                                                do {
                                                    $ExtensionVal = $BinaryReader.ReadByte()
                                                    # To-do: inspect to see if this is ever non-zero. It is currently unclear what these are used for.
                                                    $NewTlgEventField.Extension.Add($ExtensionVal)
                                                } while ($ExtensionVal -band 0x80)
                                            }

                                            $MaskedOutTypeVal = $OutTypeVal -band $OutTypeMask

                                            if ([Enum]::IsDefined([TlgOut], $MaskedOutTypeVal)) {
                                                $OutType = ([TlgOut] ($MaskedOutTypeVal)).ToString()
                                            } else {
                                                Write-Verbose "Unsupported field out type: 0x$($MaskedOutTypeVal.ToString('X2')); File path: $FullPath"

                                                $NewTlgEventField.OutType = $MaskedOutTypeVal.ToString()
                                            }


                                        }

                                        [UInt16] $ValueCount = 0
                                        if ($InTypeVal -band 32) {
                                            $ValueCount = $BinaryReader.ReadUInt16()
                                        }
                                        
                                        $NewTlgEventField.ValueCount = $ValueCount

                                        [UInt16] $TypeInfoSize = 0
                                        $TypeInfo = $null
                                        if (($InTypeVal -band (32 -bor 64)) -eq (32 -bor 64)) {
                                            $TypeInfoSize = $BinaryReader.ReadUInt16()

                                            [String] $TypeInfo = $BinaryReader.ReadChars($TypeInfoSize) -join ''
                                        }
                                        
                                        $NewTlgEventField.TypeInfo = $TypeInfo
                                        $NewTlgEventField.InType = ([TlgIn] ($InTypeVal -band $InTypeMask)).ToString()

                                        $NewTlgEvent.Fields.Add($NewTlgEventField)
                                    }
                                }
                            }
                        }

                        $NewTlgExecutable.EventList.Add($NewTlgEvent)
                    }

                    4 { # _TlgBlobProvider3
                        $ProviderGUID = ([Guid][Byte[]] $BinaryReader.ReadBytes(16)).Guid
                        $RemainingSize = $BinaryReader.ReadUInt16()
                        $ProviderName = $null
                        $ProviderGroupGUID = $null

                        <#
                        struct ProviderMetadata // Variable-length pseudo-structure, byte-aligned, tightly-packed.
                        {
                            UINT16 Size; // = sizeof(ProviderMetadata)
                            char Name[]; // UTF-8 nul-terminated provider name
                            ProviderMetadataChunk AdditionalProviderInfo[]; // 0 or more chunks of data.
                        };
                        // ProviderMetadataChunk:
                        struct ProviderMetadataChunk // Variable-length pseudo-structure, byte-aligned, tightly-packed.
                        {
                            UINT16 Size; // = sizeof(ProviderMetadataChunk)
                            UINT8 Type; // Value from the ETW_PROVIDER_TRAIT_TYPE enumeration.
                            AnyType Data;
                        };
                        #>

                        if ($RemainingSize) {
                            $EndPosition = $BinaryReader.BaseStream.Position + $RemainingSize - 2 # 2 - sizeof(RemainingSize)

                            # Implies that a provider name follows

                            $StrBuilder = New-Object Text.StringBuilder

                            # Build up the provider name string until a null is reached.
                            do {
                                $CharVal = $BinaryReader.ReadChar()
                                $null = $StrBuilder.Append($CharVal)
                            } while ($CharVal -ne "`0")

                            $ProviderName = $StrBuilder.ToString().TrimEnd("`0")

                            # It is not guaranteed that chunk data will follow.
                            if ($BinaryReader.BaseStream.Position -ne $EndPosition) {
                                # Report if this is anything other than 19.
                                # I would not expect there to be any other data other than a single provider group GUID
                                $RemainingChunkSize = $BinaryReader.ReadUInt16()

                                if ($RemainingChunkSize -ne 19) {
                                    Write-Warning 'Unexpected provider metadata chunk size!'
                                }

                                if ($RemainingChunkSize) {
                                    # Refers to ETW_PROVIDER_TRAIT_TYPE in evntcons.h
                                    $ProviderAdditionalInfoTypeVal = $BinaryReader.ReadByte()

                                    switch ($ProviderAdditionalInfoTypeVal) {
                                        1 { # EtwProviderTraitTypeGroup
                                            $ProviderGroupGUID = ([Guid][Byte[]] $BinaryReader.ReadBytes(16)).Guid
                                        }

                                        2 { # EtwProviderTraitDecodeGuid
                                            # I don't expect to see this so alert if it is encountered
                                            Write-Warning 'EtwProviderTraitDecodeGuid value encountered. Inspect this manually and develop a parser.'
                                        }

                                        default {
                                            Write-Warning 'Unknown provider chunk type value encountered. Inspect this manually and develop a parser.'
                                        }
                                    }
                                }
                            }
                        }
                        
                        $NewTlgProvider = New-Object TlgProvider 
                        $NewTlgProvider.ProviderGUID = $ProviderGUID
                        $NewTlgProvider.ProviderName = $ProviderName
                        $NewTlgProvider.ProviderGroupGUID = $ProviderGroupGUID                        
                        $NewTlgExecutable.ProviderList.Add($NewTlgProvider)
                    }

                    5 { # _TlgBlobEvent2
                        <#
                          This structure type is not documented but I will do my best to infer/reverse data types.
                          Event blob structure based on reversing
                          1) byte - Level
                          2) byte - Opcode
                          3) ushort - Task
                          4) ulonglong - keyword
                          Assumed values/statis values supplied:
                          * Channel: 0xB
                          * Id: metadata offset calc
                          * Version: 0
                          Same event and field info as _TlgBlobEvent3
                        #>

                        $EventID = $BinaryReader.BaseStream.Position - $TlgSigValIndex

                        $Level = $BinaryReader.ReadByte()
                        $Opcode = $BinaryReader.ReadByte()
                        $null = $BinaryReader.ReadUInt16() # Task value. This is not relevant to trace logging
                        
                        $KeywordVal = $BinaryReader.ReadUInt64()

                        $KeywordFriendlyName = $KeywordMapping[$KeywordVal]

                        $Keyword = "0x$($KeywordVal.ToString('X16'))"
                        [Byte] $Channel = 0xB

                        $RemainingSize = $BinaryReader.ReadUInt16()

                        $ExtensionList = $null
                        $EventName = $null
                        $Fields = New-Object 'System.Collections.Generic.List[TlgEventField]' 

                        # Non-null remaining size implies that event/field metadata exists.
                        if ($RemainingSize) {

                            # Calculate the end stream position and validate along the way that it hasn't been exceeded.
                            # This is required due to how structure are stored in tightly-packed streams that don't
                            # contain fields about metadata length.
                            $EndPosition = $BinaryReader.BaseStream.Position + $RemainingSize - 2 # 2 - sizeof(RemainingSize)

                            <# What follows is an EventMetadata structure:
                                struct EventMetadata // Variable-length pseudo-structure, byte-aligned, tightly-packed.
                                {
                                    UINT16 Size; // = sizeof(EventMetadata)
                                    UINT8 Extension[]; // 1 or more bytes. Read until you hit a byte with high bit unset.
                                    char Name[]; // UTF-8 nul-terminated event name
                                    FieldMetadata Fields[]; // 0 or more field definitions.
                                };
                            #>

                            if ($BinaryReader.BaseStream.Position -ne $EndPosition) {
                                # Read extension array
                                $ExtensionList = New-Object 'System.Collections.Generic.List[Byte]'

                                do {
                                    $ExtensionVal = $BinaryReader.ReadByte()
                                    # To-do: inspect to see if this is ever non-zero. It is currently unclear what these are used for.
                                    $ExtensionList.Add($ExtensionVal)
                                } while ($ExtensionVal -band 0x80)

                                if ($BinaryReader.BaseStream.Position -ne $EndPosition) {
                                    $StrBuilder = New-Object Text.StringBuilder

                                    # Build up the event name string until a null is reached.
                                    do {
                                        $CharVal = $BinaryReader.ReadChar()
                                        $null = $StrBuilder.Append($CharVal)
                                    } while ($CharVal -ne "`0")

                                    $EventName = $StrBuilder.ToString().TrimEnd("`0")

                                    while ($BinaryReader.BaseStream.Position -lt $EndPosition) {

                                        # Parse out all fields in the event. Fields are optional.
                                        <#
                                        struct FieldMetadata // Variable-length pseudo-structure, byte-aligned, tightly-packed.
                                        {
                                            char Name[]; // UTF-8 nul-terminated field name
                                            UINT8 InType; // Values from the TlgIn enumeration.
                                            UINT8 OutType; // TlgOut enumeration. Only present if (InType & 128) == 128.
                                            UINT8 Extension[]; // Only present if OutType is present and (OutType & 128) == 128. Read until you hit a byte with high bit unset.
                                            UINT16 ValueCount;  // Only present if (InType & CountMask) == Ccount.
                                            UINT16 TypeInfoSize; // Only present if (InType & CountMask) == Custom.
                                            char TypeInfo[TypeInfoSize]; // Only present if (InType & CountMask) == Custom.
                                        };
                                        #>

                                        # Build up the field name string until a null is reached.
                                        $StrBuilder = New-Object Text.StringBuilder

                                        do {
                                            $CharVal = $BinaryReader.ReadChar()
                                            $null = $StrBuilder.Append($CharVal)
                                        } while ($CharVal -ne "`0")

                                        $FieldName = $StrBuilder.ToString().TrimEnd("`0")

                                        $InTypeVal = $BinaryReader.ReadByte()

                                        $InTypeMask = 31

                                        <#
                                        if ($InTypeVal -band 64) {
                                            Write-Warning "VCount Tag Flag Encountered! Current position: 0x$($BinaryReader.BaseStream.Position.ToString('X8'))"
                                        }
                                        #>

                                        $OutType = $null
                                        $OutTypeVal = $null
                                        $FieldExtensionList = $null

                                        if ($InTypeVal -band 128) {
                                            # This means that the OutType field is populated.
                                            $OutTypeVal = $BinaryReader.ReadByte()

                                            $OutTypeMask = 127

                                            if ($OutTypeVal -band 128) {
                                                $FieldExtensionList = New-Object 'System.Collections.Generic.List[Byte]'

                                                do {
                                                    $ExtensionVal = $BinaryReader.ReadByte()
                                                    # To-do: inspect to see if this is ever non-zero. It is currently unclear what these are used for.
                                                    $FieldExtensionList.Add($ExtensionVal)
                                                } while ($ExtensionVal -band 0x80)
                                            }

                                            $MaskedOutTypeVal = $OutTypeVal -band $OutTypeMask

                                            if ([Enum]::IsDefined([TlgOut], $MaskedOutTypeVal)) {
                                                $OutType = ([TlgOut] ($MaskedOutTypeVal)).ToString()
                                            } else {
                                                Write-Verbose "Unsupported field out type: 0x$($MaskedOutTypeVal.ToString('X2')); File path: $FullPath"

                                                $OutType = $MaskedOutTypeVal.ToString()
                                            }


                                        }

                                        [UInt16] $ValueCount = 0
                                        if ($InTypeVal -band 32) {
                                            $ValueCount = $BinaryReader.ReadUInt16()
                                        }

                                        [UInt16] $TypeInfoSize = 0
                                        $TypeInfo = $null
                                        if (($InTypeVal -band (32 -bor 64)) -eq (32 -bor 64)) {
                                            $TypeInfoSize = $BinaryReader.ReadUInt16()

                                            [String] $TypeInfo = $BinaryReader.ReadChars($TypeInfoSize) -join ''
                                        }

                                        $InType = ([TlgIn] ($InTypeVal -band $InTypeMask)).ToString()
                                        
                                        $NewTlgField = New-Object TlgEventField
                                        $NewTlgField.FieldName = $FieldName
                                        $NewTlgField.InType = $InType
                                        $NewTlgField.OutType = $OutType
                                        $NewTlgField.Extension = $FieldExtensionList
                                        $NewTlgFIeld.ValueCount = $ValueCount
                                        $NewTlgField.TypeInfo = $TypeInfo
                                        
                                        $Fields.Add($NewTlgFIeld)
                                    }
                                }
                            }
                        }
                        
                        $NewTlgEvent = New-Object TlgEvent
                        $NewTlgEvent.EventID = $EventID
                        $NewTlgEvent.Channel = $Channel
                        $NewTlgEvent.Level = $Level
                        $NewTlgEvent.Opcode = $Opcode
                        $NewTlgEvent.Keyword = $Keyword
                        $NewTlgEvent.KeywordName = $KeywordFriendlyName
                        $NewTlgEvent.Extension = $ExtensionList
                        $NewTlgEvent.EventName = $EventName
                        $NewTlgEvent.Fields = $Fields

                        $NewTlgExecutable.EventList.Add($NewTlgEvent)
                    }
                    
                    6 { # _TlgBlobEvent4 Same as _TlgBlobEvent4 but EventID is always 0. Thanks Alex Ionescu for the explanation!

                        $Channel = $BinaryReader.ReadByte() # This _should_ always be 11 (TraceLogging - Event contains provider traits and TraceLogging event metadata.)
                        $Level = $BinaryReader.ReadByte()
                        $Opcode = $BinaryReader.ReadByte()

                        $KeywordVal = $BinaryReader.ReadUInt64()

                        $KeywordFriendlyName = $KeywordMapping[$KeywordVal]

                        $Keyword = "0x$($KeywordVal.ToString('X16'))"
                        $RemainingSize = $BinaryReader.ReadUInt16()

                        $ExtensionList = $null
                        $EventName = $null
                        $Fields = $null

                        # Non-null remaining size implies that event/field metadata exists.
                        if ($RemainingSize) {

                            # Calculate the end stream position and validate along the way that it hasn't been exceeded.
                            # This is required due to how structure are stored in tightly-packed streams that don't
                            # contain fields about metadata length.
                            $EndPosition = $BinaryReader.BaseStream.Position + $RemainingSize - 2 # 2 - sizeof(RemainingSize)

                            <# What follows is an EventMetadata structure:
                                struct EventMetadata // Variable-length pseudo-structure, byte-aligned, tightly-packed.
                                {
                                    UINT16 Size; // = sizeof(EventMetadata)
                                    UINT8 Extension[]; // 1 or more bytes. Read until you hit a byte with high bit unset.
                                    char Name[]; // UTF-8 nul-terminated event name
                                    FieldMetadata Fields[]; // 0 or more field definitions.
                                };
                            #>

                            if ($BinaryReader.BaseStream.Position -ne $EndPosition) {
                                # Read extension array
                                $ExtensionList = New-Object 'System.Collections.Generic.List[Byte]'

                                do {
                                    $ExtensionVal = $BinaryReader.ReadByte()
                                    # To-do: inspect to see if this is ever non-zero. It is currently unclear what these are used for.
                                    $ExtensionList.Add($ExtensionVal)
                                } while ($ExtensionVal -band 0x80)

                                if ($BinaryReader.BaseStream.Position -ne $EndPosition) {
                                    $StrBuilder = New-Object Text.StringBuilder

                                    # Build up the event name string until a null is reached.
                                    do {
                                        $CharVal = $BinaryReader.ReadChar()
                                        $null = $StrBuilder.Append($CharVal)
                                    } while ($CharVal -ne "`0")

                                    $EventName = $StrBuilder.ToString().TrimEnd("`0")

                                    $Fields = New-Object 'System.Collections.Generic.List[TlgEventField]'

                                    while ($BinaryReader.BaseStream.Position -lt $EndPosition) {

                                        # Parse out all fields in the event. Fields are optional.
                                        <#
                                        struct FieldMetadata // Variable-length pseudo-structure, byte-aligned, tightly-packed.
                                        {
                                            char Name[]; // UTF-8 nul-terminated field name
                                            UINT8 InType; // Values from the TlgIn enumeration.
                                            UINT8 OutType; // TlgOut enumeration. Only present if (InType & 128) == 128.
                                            UINT8 Extension[]; // Only present if OutType is present and (OutType & 128) == 128. Read until you hit a byte with high bit unset.
                                            UINT16 ValueCount;  // Only present if (InType & CountMask) == Ccount.
                                            UINT16 TypeInfoSize; // Only present if (InType & CountMask) == Custom.
                                            char TypeInfo[TypeInfoSize]; // Only present if (InType & CountMask) == Custom.
                                        };
                                        #>

                                        # Build up the field name string until a null is reached.
                                        $StrBuilder = New-Object Text.StringBuilder

                                        do {
                                            $CharVal = $BinaryReader.ReadChar()
                                            $null = $StrBuilder.Append($CharVal)
                                        } while ($CharVal -ne "`0")

                                        $FieldName = $StrBuilder.ToString().TrimEnd("`0")

                                        $InTypeVal = $BinaryReader.ReadByte()

                                        $InTypeMask = 31

                                        <#
                                        if ($InTypeVal -band 64) {
                                            Write-Warning "VCount Tag Flag Encountered! Current position: 0x$($BinaryReader.BaseStream.Position.ToString('X8'))"
                                        }
                                        #>

                                        $OutType = $null
                                        $OutTypeVal = $null
                                        $FieldExtensionList = $null

                                        if ($InTypeVal -band 128) {
                                            # This means that the OutType field is populated.
                                            $OutTypeVal = $BinaryReader.ReadByte()

                                            $OutTypeMask = 127

                                            if ($OutTypeVal -band 128) {
                                                $FieldExtensionList = New-Object 'System.Collections.Generic.List[Byte]'

                                                do {
                                                    $ExtensionVal = $BinaryReader.ReadByte()
                                                    # To-do: inspect to see if this is ever non-zero. It is currently unclear what these are used for.
                                                    $FieldExtensionList.Add($ExtensionVal)
                                                } while ($ExtensionVal -band 0x80)
                                            }

                                            $MaskedOutTypeVal = $OutTypeVal -band $OutTypeMask

                                            if ([Enum]::IsDefined([TlgOut], $MaskedOutTypeVal)) {
                                                $OutType = ([TlgOut] ($MaskedOutTypeVal)).ToString()
                                            } else {
                                                Write-Verbose "Unsupported field out type: 0x$($MaskedOutTypeVal.ToString('X2')); File path: $FullPath"

                                                $OutType = $MaskedOutTypeVal.ToString()
                                            }


                                        }

                                        [UInt16] $ValueCount = 0
                                        if ($InTypeVal -band 32) {
                                            $ValueCount = $BinaryReader.ReadUInt16()
                                        }

                                        [UInt16] $TypeInfoSize = 0
                                        $TypeInfo = $null
                                        if (($InTypeVal -band (32 -bor 64)) -eq (32 -bor 64)) {
                                            $TypeInfoSize = $BinaryReader.ReadUInt16()

                                            [String] $TypeInfo = $BinaryReader.ReadChars($TypeInfoSize) -join ''
                                        }

                                        $InType = ([TlgIn] ($InTypeVal -band $InTypeMask)).ToString()
                                        
                                        $NewTlgField = New-Object 'TlgEventField'
                                        $NewTlgField.FieldName = $FieldName
                                        $NewTlgField.InType = $InType
                                        $NewTlgField.OutType = $OutType
                                        $NewTlgField.Extension = $FieldExtensionList
                                        $NewTlgField.ValueCount = $ValueCount
                                        $NewTlgField.TypeInfo = $TypeInfo
                                        
                                        $Fields.Add($NewTlgField)
                                    }
                                }
                            }
                        }

                        $NewTlgEvent = New-Object TlgEvent
                        $NewTlgEvent.EventId = 0
                        $NewTlgEvent.Channel = $Channel
                        $NewTlgEvent.Level = $Level
                        $NewTlgEvent.Opcode = $Opcode
                        $NewTlgEvent.Keyword = $Keyword
                        $NewTlgEvent.KeywordName = $KeywordFriendlyName
                        $NewTlgEvent.Extension = $ExtensionList
                        $NewTlgEvent.EventName = $EventName
                        $NewTlgEvent.Fields = $Fields

                        $NewTlgExecutable.EventList.Add($NewTlgEvent)
                    }

                    default {
                        # To-do: logic goes here to account for unparsed structures.
                        # e.g. I will need to get to parsing provider metadata next.
                        Write-Error "Unparsed blob type enountered! Blob type val: 0x$($BlobType.ToString('X2')); File path: $FullPath; Current position: 0x$($BinaryReader.BaseStream.Position.ToString('X8'))"
                    }
                }

                $BlobType = $BinaryReader.ReadByte()
            }
        }
        $BinaryReader.Close()
    }

    $StreamReader.Close()
    $MemoryStream.Close()

    return $NewTlgExecutable
}


foreach ($fileName in [IO.Directory]::EnumerateFiles("c:\windows\system32")) 
{

    if (-not ($fileName.EndsWith(".exe") -or $fileName.EndsWith(".dll"))) {
        continue
    }
    [Console]::WriteLine("Finding providers in " + $fileName + "...")
    try {
        $Output = Get-TraceLoggingMetadata -Path $fileName
    }
    catch {
        Write-Host "An error occurred:"
        Write-Host $_
        continue
    }
    
    if ($Output.ProviderList.Length -eq 0) {
        continue
    }
    
    [Console]::WriteLine("Converting output to JSON...")
    $Output = ConvertTo-Json -InputObject $Output -Depth 5
    $jsonFileName = "json\\" + [IO.Path]::GetFileNameWithoutExtension($fileName) + ".json"
    [Console]::WriteLine("Writing output to " + $jsonFileName)
    [IO.File]::WriteAllText($jsonFileName, $Output)

}