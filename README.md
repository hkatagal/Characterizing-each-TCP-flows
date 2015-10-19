# Characterizing-each-TCP-flows
TASK 1:
Instructions to Compile and Run Assign2 program.

Step 1: 	To compile the code from command line, type the following:

		g++ Assign2.cpp -o Assign2 -lpcap
		
Step 2:	To run the code from command line, type the following:

		./Assign2 test.pcap
		
The output of the program is displayed on the console, and also recorded in a text file “Output.txt”. 

Explanation for the computations:

1.	Number of retransmissions: A packet is considered retransmitted if it has the same sequence number as that of the already received packet. We computed this by storing the sequence numbers of the received packets and comparing that number with the sequence numbers already recorded.

2.	Number of out-of-order packets: The receiver can estimate the sequence number of next packet by adding the sequence number of current packet with the payload length. By comparing this value with the sequence number of the next packet we can find if the out-of-order packet.

3.	Throughput: This is calculated by recording the total bytes of all the packets and dividing it by time duration of the connection.

4.	Goodput: This is calculated by recording the total bytes of data payload in all the packets and dividing it by time duration of the connection.

5.	Receiver/Sender Window Size: This is calculated by multiplying the Window size value in the packet by the scaling factor which can be obtained from the SYN/SYN ACK packets. The scaling factor is calculated as the power of 2 raised to the shift bit of the SYN/SYN ACK packet.

6.	Congestion Window Size

