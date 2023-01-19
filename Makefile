DBFLAGS=-g -O0 -DDEBUG
NDBFLAGS=-O2
CFLAGS=-Wall -Werror
OUTDIR=build
OUTPUT=$(OUTDIR)/scap_read

FALCO_LIBS=$(OUTDIR)/falco_libs
INCLUDES+=-I $(FALCO_LIBS)/userspace/libscap
INCLUDES+=-I $(FALCO_LIBS)/userspace/libscap/engine/savefile

CFILES=scap_read.c read_proclist.c

all: debug

$(OUTDIR):
	mkdir -p $(OUTDIR)

debug: $(CFILES) $(OUTDIR) $(FALCO_LIBS)
	gcc $(CFLAGS) $(DBFLAGS) $(INCLUDES) -o $(OUTPUT) $(CFILES)

release: $(CFILES) $(OUTDIR) $(FALCO_LIBS)
	gcc $(CFLAGS) $(NDBFLAGS) $(INCLUDES) -o $(OUTPUT) $(CFILES)

$(FALCO_LIBS):
	git clone https://github.com/falcosecurity/libs.git $(FALCO_LIBS)

clean:
	-rm -rf $(OUTPUT) $(OUTDIR)

