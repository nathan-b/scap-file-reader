DBFLAGS=-g -O0 -DDEBUG
NDBFLAGS=-O2
CFLAGS=-Wall -Werror
OUTDIR=build
OUTPUT=$(OUTDIR)/scap_read

FALCO_LIBS=$(OUTDIR)/falco_libs
INCLUDES+=-I $(FALCO_LIBS)/userspace
INCLUDES+=-I $(FALCO_LIBS)/userspace/libscap
INCLUDES+=-I $(FALCO_LIBS)/userspace/libscap/engine/savefile
INCLUDES+=-I $(OUTDIR)

CFILES=scap_read.c read_proclist.c bufscap.c largest_block.c

all: debug

$(OUTDIR):
	mkdir -p $(OUTDIR)

debug: $(CFILES) $(OUTDIR) $(FALCO_LIBS) $(OUTDIR)/block_types.h
	gcc $(CFLAGS) $(DBFLAGS) $(INCLUDES) -o $(OUTPUT) $(CFILES)

release: $(CFILES) $(OUTDIR) $(FALCO_LIBS) $(OUTDIR)/block_types.h
	gcc $(CFLAGS) $(NDBFLAGS) $(INCLUDES) -o $(OUTPUT) $(CFILES)

$(FALCO_LIBS):
	git clone https://github.com/falcosecurity/libs.git $(FALCO_LIBS)

$(OUTDIR)/block_types.h: $(FALCO_LIBS)
	./block_name_parser.rb build/falco_libs/userspace/libscap/scap_savefile.h > $(OUTDIR)/block_types.h

clean:
	-rm -rf $(OUTPUT) $(OUTDIR)
