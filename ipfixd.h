#include <stdint.h>

struct ipfix_msg_header {
	/*
	 * The value of this field is 0x000a for the current version.
	 */
	uint16_t version_number;

	/*
	 * Total length of the IPFIX Message, measured in octets,
	 * including Message Header and Set(s).
	 */
	uint16_t length;

	/*
	 * Time at which the IPFIX Message Header leaves the Exporter
	 * (UNIX epoch, seconds).
	 */
	uint32_t export_time;

	/*
	 * Incremental sequence counter
	 */
	uint32_t sequence_number;

	/*
	 * A 32-bit identifier of the Observation Domain that is locally
	 * unique to the Exporting Process.
	 */
	uint32_t observation_domain_id;
};

struct set_header {
	/*
	 * Identifies the Set.
	 *   0-1: not used
	 *     2: Template Sets
	 *     3: Options Template Sets
	 * 4-255: future use
	 *  256-: Data Sets
	 */
	 uint16_t set_id;

	 /*
	  * Total length of the Set, in octets, including the Set Header,
	  * all records, and the optional padding.
	  */
	 uint16_t length;
};


