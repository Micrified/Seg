#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <signal.h>
#include <errno.h>
#include <sys/mman.h>
#include <inttypes.h>
#include "pmap.h"

#define FAULT_FORMAT	"--- Segmentation Fault ---\n"\
						" inst: %p\n"\
						" addr: %p\n"\
						"--------------------------\n"

/*
 *******************************************************************************
 *                              Global Variables                               *
 *******************************************************************************
*/


// Heap Variable.
int v;

// The page size.
int pagesize;

// Pointer to allocated page.
void *page;


/*
 *******************************************************************************
 *                               Signal Handlers                               *
 *******************************************************************************
*/

void protectJust (void *addr, size_t size, int perms);

// Handler: Segmentation Fault.
void handler (int signal, siginfo_t *info, void *context) {
	printf(FAULT_FORMAT, info->si_ptr, info->si_addr);
	exit(EXIT_FAILURE);
}

/*
 *******************************************************************************
 *                                  Routines                                   *
 *******************************************************************************
*/

// Configures a signal handler, then returns it's pointer. Use for ONE signal.
void setHandler (int signal, void (*f)(int, siginfo_t *, void *)) {
	static struct sigaction handler;		
	handler.sa_flags = SA_SIGINFO;			// Set to use signal-handler.
	sigemptyset(&handler.sa_mask);			// Zero-out bits.
	handler.sa_sigaction = f;				// Assign handler function.

	// Specify signal action: Verify success.
	if (sigaction(signal, &handler, NULL) == -1) {
		fprintf(stderr, "Error: sigaction(%d, %p, NULL) failed: %s\n", 
			signal, &handler, strerror(errno));
		exit(EXIT_FAILURE);
	}
}

// Protects specific slice of memory starting from given address.
void protectJust (void *addr, size_t size, int perms) {
	ProcMap pm;

	// Open memory mappings for this process.
	if (openProcMaps(getpid()) == 0) {
		fprintf(stderr, "Error: Couldn't open procmaps!\n");
		exit(EXIT_FAILURE);
	}

	// Locate and print region containing given address.
	while (parseNext(&pm)) {
		if (pm.startAddress <= addr && pm.endAddress >= addr) {
			break;
		}
	}
	printf("protectJust: Addr in page \"%s\": Check: %p <= %p <= %p, Perms: %s\n", 
		pm.filePath, pm.startAddress, addr, pm.endAddress, pm.perms);

	// Compute the offset of the address.
	size_t offset = (uintptr_t)addr % (uintptr_t)pagesize;

	// Compute starting address of the page.
	void *start = addr - offset;

	// Apply protection to page up to addr + size - 1.
	if (mprotect(start, offset + size, perms) == -1) {
		fprintf(stderr, "Error: mprotect(%p, %d, %d) failed: %s\n", page,
			pagesize, perms, strerror(errno));
		exit(EXIT_FAILURE);
	}
	printf("protectJust: Applied %d across range: [%p .. %p]\n", perms, start, start + offset + size - 1);

	// Re-apply protection to page up to addr - 1. 
	if (mprotect(start, offset, PROT_READ | PROT_EXEC | PROT_WRITE) == -1) {
		fprintf(stderr, "Error: mprotect(%p, %d, %d) failed: %s\n", page,
			pagesize, perms, strerror(errno));
		exit(EXIT_FAILURE);		
	}
	printf("protectJust: Reset permissions across range: [%p .. %p]\n", start, start + offset - 1);
	closeProcMaps();
}

// Protects memory page for the given address. 
void protect (void *addr, int perms) {
	
	// Compute starting address of the page.
	void *page = addr - ((uintptr_t)addr % (uintptr_t)pagesize);

	// Apply protections and verify outcome.
	if (mprotect(page, pagesize, perms) == -1) {
		fprintf(stderr, "Error: mprotect(%p, %d, %d) failed: %s\n", page,
			pagesize, perms, strerror(errno));
		exit(EXIT_FAILURE);
	}
}
 
int main (void) {

	// Set page size.
	pagesize = sysconf(_SC_PAGE_SIZE);

	// Configure a handler for SIGSEGV.
	setHandler(SIGSEGV, handler);

	// Allocate aligned page.
	if (posix_memalign(&page, pagesize, pagesize) != 0) {
		fprintf(stderr, "Error: Couldn't allocated aligned page: %s\n", 
			strerror(errno));
		exit(EXIT_FAILURE);
	}

	// For testing, either: 
	// 1. Use global (pre-allocated) heap variable: v
	// 2. Use allocated page (dedicated): heap		

	int *p = &v;


	protectJust(p, sizeof(int), PROT_READ);

	*p = 0;


	return 0;
}