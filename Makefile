all:1m_block

1m_block: 1m_block.cpp
	g++ -std=c++11 1m_block.cpp -o 1m_block -lnetfilter_queue

clean:
	rm -f 1m_block 
