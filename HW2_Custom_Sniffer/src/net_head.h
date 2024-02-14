/*
 *  Communication and Computing Course Assigment 5
 *  Copyright (C) 2023  Roy Simanovich and Yuval Yurzdichinsky
 *
 *  This program is free software: you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation, either version 3 of the License, or
 *  (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program.  If not, see <https://www.gnu.org/licenses/>.
 */

#ifndef _NET_HEAD_H
#define _NET_HEAD_H

/***********************/
/* Definitions section */
/**********************/

/*
 * @brief The maximum length of the name of a network interface card (NIC).
 * @note The default value is 128 characters.
 */
#define MAX_DEV_NAME 128

/*******************/
/* Structs section */
/*******************/

/*
 * @brief The calculator packet header.
 * @param unixtime The time that the packet was sent, in seconds since 1970-01-01 00:00:00 UTC.
 * @param length The total length of the packet, in bytes (including the header and the data).
 * @param flags The flags of the packet.
 * @param cache The 'Max-Age' value for the cache.
 * @param __ Padding for future use, do not use.
 * @note The field size is 12 bytes (3 words).
 */
typedef struct _calculatorPacket
{
	/*
	 * @brief The time that the packet was sent, in seconds since 1970-01-01 00:00:00 UTC.
	 * @note The minimum value is 0 and the maximum value is 4294967295.
	 * @note Field size is 4 bytes (32 bits).
	 * @attention The field is in network byte-order, so it should be converted to host byte-order.
	 */
	uint32_t unixtime;

	/*
	 * @brief The total length of the packet, in bytes (including the header and the data).
	 * @note The minimum value is 12 bytes (header only) and the maximum value is 8180 bytes.
	 * @note Field size is 2 bytes (16 bits).
	 * @attention The field is in network byte-order, so it should be converted to host byte-order.
	 */
	uint16_t length;

	/*
	 * @brief Union struct to use the netowrk byte-order to host byte-order to all fields at one time.
	 * @note The field size is 2 bytes (16 bits).
	 */
	union
	{
		/*
		 * @brief The flags of the packet.
		 * @note Field size is 2 bytes (16 bits).
		 * @attention The field is in network byte-order, so it should be converted to host byte-order.
		 */
		uint16_t flags;

		/*
		 * @brief This field is reserved for future use.
		 * @note The field size is 3 bits.
		 * @attention Do not use this field.
		 */
		uint16_t _ : 3,

			/*
			 * @brief Whether to cache the packet or not.
			 * @note The field size is 1 bit.
			 * @attention Only use the first bit of the field.
			 */
			c_flag : 1,

			/*
			 * @brief Whether to include the computation steps in the response.
			 * @note The field size is 1 bit.
			 * @attention Only use the first bit of the field.
			 */
			s_flag : 1,

			/*
			 * @brief Whether the packet is a request or a response.
			 * @note The field size is 1 bit.
			 * @attention Only use the first bit of the field.
			 */
			t_flag : 1,

			/*
			 * @brief The status code of the response.
			 * @note The field size is 10 bits.
			 * @attention Only use the first 10 bits of the field.
			 */
			status : 10;
	} un;

	/*
	 * @brief The 'Max-Age' value for the cache.
	 * @note If the 'Cache' flag is not set, this value is
	 * @note ignored. If the value is the maximum value for a 16-bit unsigned integer (65535),
	 * @note the cache will never expire. For requests, this is the maximum age of the cached
	 * @note response that the client is willing to accept (in seconds). This means that the
	 * @note cache shouldn't return a cached response older then this value. If max-age is 0,
	 * @note the server must recompute the response regardless of whether it is cached or not.
	 * @note For responses, this is the maximum time that the response can be cached for
	 * @note (in seconds). If max-age is 0, the response must not be cached.
	 * @note The field size is 2 bytes (16 bits).
	 * @attention The field is in network byte-order, so it should be converted to host byte-order.
	 */
	uint16_t cache;

	/*
	 * @brief Padding for future use.
	 * @note The field size is 2 bytes (16 bits).
	 * @attention Do not use this field.
	 */
	uint16_t __;
} CPacket, *PCPacket;

/*********************/
/* Functions section */
/*********************/

/*
 * @brief A sniffing packet function, using the PCAP library.
 * @param args arguments.
 * @param header the pcap header of the packet.
 * @param packet the packet itself.
 * @return void
 */
void packetSniffer(u_char *args, const struct pcap_pkthdr *header, const u_char *packet);

#endif /* _NET_HEAD_H */