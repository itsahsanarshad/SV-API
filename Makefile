CXX = g++
CXXFLAGS = -std=c++17 -Wall \
    -Ilib/Crow/include \
    -Ilib/asio/asio/include \
    -Ilib/jwt-cpp/include \
    -Isrc \
    -I/usr/local/opt/libpqxx/include \
    -I/usr/local/opt/libpq/include

LDFLAGS = -L/usr/local/opt/libpqxx/lib \
    -L/usr/local/opt/libpq/lib \
    -lpthread -lpqxx -lpq -lssl -lcrypto

SRC = src/main.cpp
TARGET = crow_app

all: $(TARGET)

$(TARGET): $(SRC)
	$(CXX) $(CXXFLAGS) -o $(TARGET) $(SRC) $(LDFLAGS)

clean:
	rm -f $(TARGET)

.PHONY: all clean
