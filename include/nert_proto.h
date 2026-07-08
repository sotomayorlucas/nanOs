#ifndef NERT_PROTO_H
#define NERT_PROTO_H
/*
 * Canonical cross-repo pheromone protocol type space + wire EtherType.
 * SINGLE source of truth, shared by micrOs (Queen) and nanOs (workers). The
 * encrypted NERT path on both repos already dispatches with these values.
 * nanOs's private raw namespace (KV/SENSOR/TERRAIN/... and NANOS_RAW_*) is
 * separate and defined in nanos.h. Do not add nanOs-internal types here.
 */
#ifndef PHEROMONE_ECHO
#define PHEROMONE_ECHO             0x00
#endif
#ifndef PHEROMONE_ANNOUNCE
#define PHEROMONE_ANNOUNCE         0x01   /* presence beacon; nanOs HELLO == this */
#endif
#ifndef PHEROMONE_ELECTION
#define PHEROMONE_ELECTION         0x02
#endif
#ifndef PHEROMONE_REKEY
#define PHEROMONE_REKEY            0x03
#endif
#ifndef PHEROMONE_DATA
#define PHEROMONE_DATA             0x10
#endif
#ifndef PHEROMONE_ALARM
#define PHEROMONE_ALARM            0x11
#endif
#ifndef PHEROMONE_COMMAND
#define PHEROMONE_COMMAND          0x12
#endif
#ifndef PHEROMONE_DIE
#define PHEROMONE_DIE              0x13
#endif
#ifndef PHEROMONE_CONFIG_UPDATE
#define PHEROMONE_CONFIG_UPDATE    0x14
#endif
#ifndef PHEROMONE_TELEMETRY_REPORT
#define PHEROMONE_TELEMETRY_REPORT 0x15
#endif
#ifndef PHEROMONE_JUDAS_ENGAGE
#define PHEROMONE_JUDAS_ENGAGE     0x16
#endif
#ifndef PHEROMONE_JUDAS_CAPTURE
#define PHEROMONE_JUDAS_CAPTURE    0x17
#endif
#ifndef PHEROMONE_JUDAS_FORENSICS
#define PHEROMONE_JUDAS_FORENSICS  0x18
#endif
#ifndef PHEROMONE_TASK_ASSIGN
#define PHEROMONE_TASK_ASSIGN      0xA0
#endif
#ifndef PHEROMONE_TASK_RESULT
#define PHEROMONE_TASK_RESULT      0xA1
#endif
#ifndef PHEROMONE_TASK_STATUS
#define PHEROMONE_TASK_STATUS      0xA2
#endif
#ifndef PHEROMONE_TASK_CANCEL
#define PHEROMONE_TASK_CANCEL      0xA3
#endif
#ifndef PHEROMONE_APP_BASE
#define PHEROMONE_APP_BASE         0xB0
#endif
/* Canonical x86 wire EtherType (host reads it big-endian on the wire as 4F 4E). */
#ifndef NERT_ETH_TYPE_WIRE
#define NERT_ETH_TYPE_WIRE         0x4F4E
#endif
#endif /* NERT_PROTO_H */
