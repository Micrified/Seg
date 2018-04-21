#include "pmap.h"

// Maximum path size.
#define MAX_PATH		1024

// Format string for process maps file path.
#define FMT_PATH		"/proc/%d/maps"

// Format string for /proc/<pid>/maps. Excludes filepath.
#define FMT_PROC		"%" SCNxPTR "-%" SCNxPTR "%4s %llx %x:%x %d"

// Format string for filepath in /proc/<pid>/maps.
#define FMT_FILE		"%*[ \t]%1023[^\n]%c"

/*
 *******************************************************************************
 *                              Global Variables                               *
 *******************************************************************************
*/

// File pointer.
//FILE *fp;

// Path buffer.
char b[MAX_PATH];

// Memory map offset.
unsigned offset; 

// Memory permissions (read, write, execute, type).
char perms[5], *p = perms;

/*
 *******************************************************************************
 *                                  Routines                                   *
 *******************************************************************************
*/

// Parse next line of map file. Set struct variables. Return zero on failure.
int parseNext (ProcMap *pm) {
	uintptr_t startAddress, endAddress;
	char n;

	// Verify file is open and pm is non-NULL.
	if (fp == NULL || pm == NULL) {
		fprintf(stderr, "Error: NULL file or ProcMap argument!\n");
		return 0;
	}

	// Verify parse success.
	if (fscanf(fp, FMT_PROC, &startAddress, &endAddress, 
		(pm->perms = p), &(pm->offset), &(pm->devMajor), &(pm->devMinor), 
		&(pm->inode)) != 7) {
		return 0;
	}

	// Check for optional filepath.
	if (fscanf(fp, FMT_FILE, b, &n) != 2 || n != '\n') {
		b[0] = '\0';
	}

	// Set addresses, and path pointer.
	pm->startAddress = (void *)startAddress;
	pm->endAddress = (void *)endAddress;
	pm->filePath = b;

	return 1;
}

// Opens a process's "maps" file. Returns zero on failure.
int openProcMaps (int pid) {

	// Construct process maps file path.
	if (sprintf(b, FMT_PATH, pid) == 0) {
		fprintf(stderr, "Error: Couldn't create file path!\n");
		return 0;
	}

	// Open file.
	if ((fp = fopen(b, "r")) == NULL) {
		fprintf(stderr, "Error: Couldn't open \"%s\"!\n", b);
		return 0;
	}

	return 1;
}

// Closes the current open maps file.
void closeProcMaps (void) {
	if (fp == NULL) {
		return;
	}

	if (fclose(fp) == EOF) {
		fprintf(stderr, "Error: Failed to close open process map file!\n");
	}
}
