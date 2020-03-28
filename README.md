# tracelogging-providers

A dump of all the trace logging providers from system32. 
I simply took [this](https://gist.github.com/mattifestation/edbac1614694886c8ef4583149f53658) script by Matt Graeber (@mattifestation) 
and run it over the system32 directory:) I tried to format the output of the script so it will be easy to view events.. For example:

```C
NegLogonUserEx2WorkerStart(
	VOID
	);

NullTargetNtlmFallback(
	VOID
	);

LoadPackages(
	INT32 status,
	UINT32 loadCount,
	UINT32 newCount,
	UINT32 indexPackage,
	UINT32 indexOldPackage,
	UNICODESTRING preferredPackageName,
	UNICODESTRING defaultTlsProviderName,
	UNICODESTRING defaultTlsProviderFileName
	);

LoadIumBoundMachineCert(
	UINT32 status,
	BOOL32 certFound
	);
```

TraceLogging can also be used to ease reverse engineering - you can write an IDA plugin to put comments with the event names.. 
I'm too lazy to do it now, maybe later :) bb