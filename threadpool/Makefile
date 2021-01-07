SRC = C-Thread-Pool/thpool.c
OBJ = $(SRC:.c=.o)
OUT = thpool.a
INCLUDES = -IC-Thread-Pool
CCFLAGS = -g -O2 -fpic
CCC = gcc
LDFLAGS = -g

.SUFFIXES: .c

all: static

static: $(OUT)

.c.o:
	$(CCC) $(INCLUDES) $(CCFLAGS) $(EXTRACCFLAGS) -c $< -o $@

$(OUT): $(OBJ)
	ar rcs $(OUT) $(OBJ)

clean:
	rm -f $(OBJ) $(OUT) $(DYN)
