include ../common.inc

PROJECT_TARGET := libstuncore.a
PROJECT_OBJS := buffer.o datastream.o messagehandler.o socketaddress.o stunbuilder.o stunclientlogic.o stunclienttests.o stunreader.o stunutils.o proxyclient.o
INCLUDES := $(BOOST_INCLUDE) $(OPENSSL_INCLUDE) -I../common -I../networkutils
LIBS := -lcurl -lnlohmann_json
CXXFLAGS += -DDEBUG

all: $(PROJECT_TARGET)

clean:
	rm -f $(PROJECT_OBJS) $(PROJECT_TARGET)

$(PROJECT_TARGET): $(PROJECT_OBJS)
	rm -f $@
	$(AR) rv $@ $^

# Add this line to ensure proper linking
%.o: %.cpp
	$(CXX) $(CXXFLAGS) $(INCLUDES) -c $< -o $@


