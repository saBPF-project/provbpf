#include "camflow_bpf_record.h"

#define MAX_JSON_BUFFER_EXP     13
#define MAX_JSON_BUFFER_LENGTH  ((1 << MAX_JSON_BUFFER_EXP)*sizeof(uint8_t))
#define BUFFER_LENGTH (MAX_JSON_BUFFER_LENGTH-strnlen(buffer, MAX_JSON_BUFFER_LENGTH))

__thread char buffer[MAX_JSON_BUFFER_LENGTH];
char date[256];
pthread_rwlock_t  date_lock;

// ideally should be derived from jiffies
void update_time( void ){
  struct tm tm;
  struct timeval tv;

  pthread_rwlock_wrlock(&date_lock);
  gettimeofday(&tv, NULL);
  gmtime_r(&tv.tv_sec, &tm);
  strftime(date, 30,"%Y:%m:%dT%H:%M:%S", &tm);
  pthread_rwlock_unlock(&date_lock);
}

void __add_attribute(const char* name, bool comma){
  if(comma){
    strncat(buffer, ",\"", BUFFER_LENGTH);
  }else{
    strncat(buffer, "\"", BUFFER_LENGTH);
  }
  strncat(buffer, name, BUFFER_LENGTH);
  strncat(buffer, "\":", BUFFER_LENGTH);
}

void __add_uint32_attribute(const char* name, const uint32_t value, bool comma){
  char tmp[32];
  __add_attribute(name, comma);
  snprintf(tmp, sizeof(tmp), "%u", value);
  strncat(buffer, tmp, BUFFER_LENGTH);
  // strncat(buffer, utoa(value, tmp, DECIMAL), BUFFER_LENGTH);
}


void __add_int32_attribute(const char* name, const int32_t value, bool comma){
  char tmp[32];
  __add_attribute(name, comma);
  snprintf(tmp, sizeof(tmp), "%d", value);
  strncat(buffer, tmp, BUFFER_LENGTH);
  // strncat(buffer, itoa(value, tmp, DECIMAL), BUFFER_LENGTH);
}

void __add_uint32hex_attribute(const char* name, const uint32_t value, bool comma){
  char tmp[32];
  __add_attribute(name, comma);
  strncat(buffer, "\"0x", BUFFER_LENGTH);
  snprintf(tmp, sizeof(tmp), "%x", value);
  strncat(buffer, tmp, BUFFER_LENGTH);
  // strncat(buffer, utoa(value, tmp, HEX), BUFFER_LENGTH);
  strncat(buffer, "\"", BUFFER_LENGTH);
}

void __add_uint64_attribute(const char* name, const uint64_t value, bool comma){
  char tmp[64];
  __add_attribute(name, comma);
  strncat(buffer, "\"", BUFFER_LENGTH);
  snprintf(tmp, sizeof(tmp), "%lu", value);
  strncat(buffer, tmp, BUFFER_LENGTH);
  // strncat(buffer, ulltoa(value, tmp, DECIMAL), BUFFER_LENGTH);
  strncat(buffer, "\"", BUFFER_LENGTH);
}

void __add_uint64hex_attribute(const char* name, const uint64_t value, bool comma){
  char tmp[64];
  __add_attribute(name, comma);
  strncat(buffer, "\"", BUFFER_LENGTH);
  snprintf(tmp, sizeof(tmp), "%lx", value);
  strncat(buffer, tmp, BUFFER_LENGTH);
  // strncat(buffer, ulltoa(value, tmp, HEX), BUFFER_LENGTH);
  strncat(buffer, "\"", BUFFER_LENGTH);
}

void __add_int64_attribute(const char* name, const int64_t value, bool comma){
  char tmp[64];
  __add_attribute(name, comma);
  strncat(buffer, "\"", BUFFER_LENGTH);
  snprintf(tmp, sizeof(tmp), "%ld", value);
  strncat(buffer, tmp, BUFFER_LENGTH);
  // strncat(buffer, lltoa(value, tmp, DECIMAL), BUFFER_LENGTH);
  strncat(buffer, "\"", BUFFER_LENGTH);
}

void __add_string_attribute(const char* name, const char* value, bool comma){
  if(value[0]=='\0'){ // value is not set
    return;
  }
  __add_attribute(name, comma);
  strncat(buffer, "\"", BUFFER_LENGTH);
  strncat(buffer, value, BUFFER_LENGTH);
  strncat(buffer, "\"", BUFFER_LENGTH);
}

void __add_date_attribute(bool comma){
  __add_attribute("cf:date", comma);
  strncat(buffer, "\"", BUFFER_LENGTH);
  pthread_rwlock_rdlock(&date_lock);
  strncat(buffer, date, BUFFER_LENGTH);
  pthread_rwlock_unlock(&date_lock);
  strncat(buffer, "\"", BUFFER_LENGTH);
}

#define UUID_STR_SIZE 37
char* uuid_to_str(uint8_t* uuid, char* str, size_t size){
  if(size<37){
    snprintf(str, size, "UUID-ERROR");
    return str;
  }
  snprintf(str, size, "%02x%02x%02x%02x-%02x%02x-%02x%02x-%02x%02x-%02x%02x%02x%02x%02x%02x",
    uuid[0], uuid[1], uuid[2], uuid[3]
    , uuid[4], uuid[5]
    , uuid[6], uuid[7]
    , uuid[8], uuid[9]
    , uuid[10], uuid[11], uuid[12], uuid[13], uuid[14], uuid[15]);
    return str;
}

void __add_ipv4(uint32_t ip, uint32_t port){
    char tmp[8];
    strncat(buffer, uint32_to_ipv4str(ip), BUFFER_LENGTH);
    strncat(buffer, ":", BUFFER_LENGTH);
    snprintf(tmp, sizeof(tmp), "%u", htons(port));
    strncat(buffer, tmp, BUFFER_LENGTH);
    // strncat(buffer, utoa(htons(port), tmp, DECIMAL), BUFFER_LENGTH);
}

void __add_ipv4_attribute(const char* name, const uint32_t ip, const uint32_t port, bool comma){
  char tmp[64];
  __add_attribute(name, comma);
  strncat(buffer, "\"", BUFFER_LENGTH);
  __add_ipv4(ip, port);
  strncat(buffer, "\"", BUFFER_LENGTH);
}

void __add_machine_id(uint32_t value, bool comma){
  char tmp[32];
  __add_attribute("cf:machine_id", comma);
  strncat(buffer, "\"cf:", BUFFER_LENGTH);
  snprintf(tmp, sizeof(tmp), "%u", value);
  strncat(buffer, tmp, BUFFER_LENGTH);
  // strncat(buffer, utoa(value, tmp, DECIMAL), BUFFER_LENGTH);
  strncat(buffer, "\"", BUFFER_LENGTH);
}


// -----  from libprovenance.c -----
int provenance_lib_version(char* version, size_t len){
  if(len < strlen(PROVLIB_VERSION_STR))
    return -ENOMEM;
  strncpy(version, PROVLIB_VERSION_STR, len);
  return 0;
}

int provenance_lib_commit(char* commit, size_t len){
  if(len < strlen(PROVLIB_COMMIT))
    return -ENOMEM;
  strncpy(commit, PROVLIB_COMMIT, len);
  return 0;
}
// ----------

// ------- form provenanceutils.c -----
static const char base64chars[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

// from https://en.wikibooks.org/wiki/Algorithm_Implementation/Miscellaneous/Base64#C
int base64encode(const void* data_buf, size_t dataLength, char* result, size_t resultSize){
   const uint8_t *data = (const uint8_t *)data_buf;
   size_t resultIndex = 0;
   size_t x;
   uint32_t n = 0;
   int padCount = dataLength % 3;
   uint8_t n0;
   uint8_t n1;
   uint8_t n2;
   uint8_t n3;

   /* increment over the length of the string, three characters at a time */
   for (x = 0; x < dataLength; x += 3)
   {
      /* these three 8-bit (ASCII) characters become one 24-bit number */
      n = ((uint32_t)data[x]) << 16; //parenthesis needed, compiler depending on flags can do the shifting before conversion to uint32_t, resulting to 0

      if((x+1) < dataLength)
         n += ((uint32_t)data[x+1]) << 8;//parenthesis needed, compiler depending on flags can do the shifting before conversion to uint32_t, resulting to 0

      if((x+2) < dataLength)
         n += data[x+2];

      /* this 24-bit number gets separated into four 6-bit numbers */
      n0 = (uint8_t)(n >> 18) & 63;
      n1 = (uint8_t)(n >> 12) & 63;
      n2 = (uint8_t)(n >> 6) & 63;
      n3 = (uint8_t)n & 63;

      /*
       * if we have one byte available, then its encoding is spread
       * out over two characters
       */
      if(resultIndex >= resultSize)
        return 1;   /* indicate failure: buffer too small */
      result[resultIndex++] = base64chars[n0];
      if(resultIndex >= resultSize)
        return 1;   /* indicate failure: buffer too small */
      result[resultIndex++] = base64chars[n1];

      /*
       * if we have only two bytes available, then their encoding is
       * spread out over three chars
       */
      if((x+1) < dataLength)
      {
         if(resultIndex >= resultSize)
          return 1;   /* indicate failure: buffer too small */
         result[resultIndex++] = base64chars[n2];
      }

      /*
       * if we have all three bytes available, then their encoding is spread
       * out over four characters
       */
      if((x+2) < dataLength)
      {
         if(resultIndex >= resultSize)
          return 1;   /* indicate failure: buffer too small */
         result[resultIndex++] = base64chars[n3];
      }
   }

   /*
    * create and add padding that is required if we did not have a multiple of 3
    * number of characters available
    */
   if (padCount > 0)
   {
      for (; padCount < 3; padCount++)
      {
         if(resultIndex >= resultSize)
          return 1;   /* indicate failure: buffer too small */
         result[resultIndex++] = '=';
      }
   }
   if(resultIndex >= resultSize)
    return -1;   /* indicate failure: buffer too small */
   result[resultIndex] = 0;
   return 0;   /* indicate success */
}
// -----------

// ----------------------------------
const static char prefix[] = "\"prov\" : \"http://www.w3.org/ns/prov\", \"cf\":\"http://www.camflow.org\"";
const char* prefix_json(){
  return prefix;
}

static pthread_mutex_t l_flush =  PTHREAD_RECURSIVE_MUTEX_INITIALIZER_NP;
static pthread_mutex_t l_activity =  PTHREAD_RECURSIVE_MUTEX_INITIALIZER_NP;
static pthread_mutex_t l_agent =  PTHREAD_RECURSIVE_MUTEX_INITIALIZER_NP;
static pthread_mutex_t l_entity =  PTHREAD_RECURSIVE_MUTEX_INITIALIZER_NP;
static pthread_mutex_t l_used =  PTHREAD_RECURSIVE_MUTEX_INITIALIZER_NP;
static pthread_mutex_t l_generated =  PTHREAD_RECURSIVE_MUTEX_INITIALIZER_NP;
static pthread_mutex_t l_informed =  PTHREAD_RECURSIVE_MUTEX_INITIALIZER_NP;
static pthread_mutex_t l_influenced =  PTHREAD_RECURSIVE_MUTEX_INITIALIZER_NP;
static pthread_mutex_t l_associated =  PTHREAD_RECURSIVE_MUTEX_INITIALIZER_NP;
static pthread_mutex_t l_derived =  PTHREAD_RECURSIVE_MUTEX_INITIALIZER_NP;
static pthread_mutex_t l_message =  PTHREAD_RECURSIVE_MUTEX_INITIALIZER_NP;

static char* activity;
static char* agent;
static char* entity;
static char* used;
static char* generated;
static char* informed;
static char* influenced;
static char* associated;
static char* derived;
static char* message;

static inline void init_buffer(char **buffer){
  *buffer = (char*)malloc(MAX_JSON_BUFFER_LENGTH);
  memset(*buffer, 0, MAX_JSON_BUFFER_LENGTH);
}

void init_buffers(void){
  init_buffer(&activity);
  init_buffer(&agent);
  init_buffer(&entity);
  init_buffer(&used);
  init_buffer(&generated);
  init_buffer(&informed);
  init_buffer(&influenced);
  init_buffer(&associated);
  init_buffer(&derived);
  init_buffer(&message);
}

static bool writing_out = false;

static void (*print_json)(char* json);

void set_W3CJSON_callback( void (*fcn)(char* json) ){
  init_buffers();
  print_json = fcn;
}

static inline bool __append(char destination[MAX_JSON_BUFFER_LENGTH], char* source){
  if (strlen(source) + 2 > MAX_JSON_BUFFER_LENGTH - strlen(destination) - 1){ // not enough space
    return false;
  }
  // add the comma
  if(destination[0]!='\0')
    strncat(destination, ",", MAX_JSON_BUFFER_LENGTH - strlen(destination) - 1);
  strncat(destination, source, MAX_JSON_BUFFER_LENGTH - strlen(destination) - 1); // copy up to free space
  return true;
}

#define JSON_START "{\"prefix\":{"
#define JSON_ACTIVITY "}, \"activity\":{"
#define JSON_AGENT "}, \"agent\":{"
#define JSON_ENTITY "}, \"entity\":{"
#define JSON_MESSAGE "}, \"message\":{"
#define JSON_USED "}, \"used\":{"
#define JSON_GENERATED "}, \"wasGeneratedBy\":{"
#define JSON_INFORMED "}, \"wasInformedBy\":{"
#define JSON_INFLUENCED "}, \"wasInfluencedBy\":{"
#define JSON_ASSOCIATED "}, \"wasAssociatedWith\":{"
#define JSON_DERIVED "}, \"wasDerivedFrom\":{"
#define JSON_END "}}"

#define JSON_LENGTH (strlen(JSON_START)\
                      +strlen(JSON_ACTIVITY)\
                      +strlen(JSON_AGENT)\
                      +strlen(JSON_ENTITY)\
                      +strlen(JSON_MESSAGE)\
                      +strlen(JSON_USED)\
                      +strlen(JSON_GENERATED)\
                      +strlen(JSON_INFORMED)\
                      +strlen(JSON_INFLUENCED)\
                      +strlen(JSON_ASSOCIATED)\
                      +strlen(JSON_DERIVED)\
                      +strlen(JSON_END)\
                      +strlen(prefix_json())\
                      +strlen(activity)\
                      +strlen(agent)\
                      +strlen(entity)\
                      +strlen(message)\
                      +strlen(used)\
                      +strlen(generated)\
                      +strlen(derived)\
                      +strlen(informed)\
                      +strlen(influenced)\
                      +strlen(associated)\
                      +1)

#define str_is_empty(str) (str[0]=='\0')

static inline bool cat_prov(char *json,
                            const char *prefix,
                            char *data,
                            pthread_mutex_t *lock){
  bool rc = false;
  if(!str_is_empty(data)){
    strncat(json, prefix, MAX_JSON_BUFFER_LENGTH);
    strncat(json, data, MAX_JSON_BUFFER_LENGTH);
    memset(data, 0, MAX_JSON_BUFFER_LENGTH);
    rc = true;
  }
  pthread_mutex_unlock(lock);
  return rc;
}

// we create the JSON string to be sent to the call back
static inline char* ready_to_print(){
  char* json;
  bool content=false;

  pthread_mutex_lock(&l_derived);
  pthread_mutex_lock(&l_influenced);
  pthread_mutex_lock(&l_associated);
  pthread_mutex_lock(&l_informed);
  pthread_mutex_lock(&l_generated);
  pthread_mutex_lock(&l_used);
  pthread_mutex_lock(&l_message);
  pthread_mutex_lock(&l_entity);
  pthread_mutex_lock(&l_agent);
  pthread_mutex_lock(&l_activity);

  json = (char*)malloc(JSON_LENGTH * sizeof(char));
  json[0]='\0';

  strncat(json, JSON_START, JSON_LENGTH);
  strncat(json, prefix_json(), JSON_LENGTH);

  content |= cat_prov(json, JSON_ACTIVITY, activity, &l_activity);
  content |= cat_prov(json, JSON_AGENT, agent, &l_agent);
  content |= cat_prov(json, JSON_ENTITY, entity, &l_entity);
  content |= cat_prov(json, JSON_MESSAGE, message, &l_message);
  content |= cat_prov(json, JSON_USED, used, &l_used);
  content |= cat_prov(json, JSON_GENERATED, generated, &l_generated);
  content |= cat_prov(json, JSON_INFORMED, informed, &l_informed);
  content |= cat_prov(json, JSON_ASSOCIATED, associated, &l_associated);
  content |= cat_prov(json, JSON_INFLUENCED, influenced, &l_influenced);
  content |= cat_prov(json, JSON_DERIVED, derived, &l_derived);

  if(!content){
    free(json);
    return NULL;
  }

  strncat(json, JSON_END, JSON_LENGTH);
  return json;
}

void flush_json(){
  bool should_flush=false;
  char* json;

  pthread_mutex_lock(&l_flush);
  if(!writing_out){
    writing_out = true;
    should_flush = true;
    update_time(); // we update the time
  }
  pthread_mutex_unlock(&l_flush);

  if(should_flush){
    json = ready_to_print();
    if(json!=NULL){
      print_json(json);
      free(json);
    }
    pthread_mutex_lock(&l_flush);
    writing_out = false;
    pthread_mutex_unlock(&l_flush);
  }
}

static inline void json_append(pthread_mutex_t* l, char destination[MAX_JSON_BUFFER_LENGTH], char* source){
  pthread_mutex_lock(l);
  // we cannot append buffer is full, need to print json out
  if(!__append(destination, source)){
    flush_json();
    pthread_mutex_unlock(l);
    json_append(l, destination, source);
    return;
  }
  pthread_mutex_unlock(l);
}

void append_activity(char* json_element){
  json_append(&l_activity, activity, json_element);
}

void append_agent(char* json_element){
  json_append(&l_agent, agent, json_element);
}

void append_entity(char* json_element){
  json_append(&l_entity, entity, json_element);
}

void append_message(char* json_element){
  json_append(&l_message, message, json_element);
}

void append_used(char* json_element){
  json_append(&l_used, used, json_element);
}

void append_generated(char* json_element){
  json_append(&l_generated, generated, json_element);
}

void append_informed(char* json_element){
  json_append(&l_informed, informed, json_element);
}

void append_influenced(char* json_element){
  json_append(&l_influenced, influenced, json_element);
}

void append_associated(char* json_element){
  json_append(&l_associated, associated, json_element);
}

void append_derived(char* json_element){
  json_append(&l_derived, derived, json_element);
}

#define BUFFER_LENGTH (MAX_JSON_BUFFER_LENGTH-strnlen(buffer, MAX_JSON_BUFFER_LENGTH))

static __thread char id[PROV_ID_STR_LEN];
static __thread char sender[PROV_ID_STR_LEN];
static __thread char receiver[PROV_ID_STR_LEN];
static __thread char parent_id[PROV_ID_STR_LEN];

#define RELATION_PREP_IDs(e) ID_ENCODE(e->identifier.buffer, PROV_IDENTIFIER_BUFFER_LENGTH, id, PROV_ID_STR_LEN);\
                        ID_ENCODE(e->snd.buffer, PROV_IDENTIFIER_BUFFER_LENGTH, sender, PROV_ID_STR_LEN);\
                        ID_ENCODE(e->rcv.buffer, PROV_IDENTIFIER_BUFFER_LENGTH, receiver, PROV_ID_STR_LEN)

#define DISC_PREP_IDs(n) ID_ENCODE(n->identifier.buffer, PROV_IDENTIFIER_BUFFER_LENGTH, id, PROV_ID_STR_LEN);\
                        ID_ENCODE(n->parent.buffer, PROV_IDENTIFIER_BUFFER_LENGTH, parent_id, PROV_ID_STR_LEN)

#define NODE_PREP_IDs(n) ID_ENCODE(n->identifier.buffer, PROV_IDENTIFIER_BUFFER_LENGTH, id, PROV_ID_STR_LEN)

#define PACKET_PREP_IDs(p) ID_ENCODE(p->identifier.buffer, PROV_IDENTIFIER_BUFFER_LENGTH, id, PROV_ID_STR_LEN)

static inline void __init_json_entry(const char* id)
{
  buffer[0]='\0';
  strncat(buffer, "\"cf:", BUFFER_LENGTH-1);
  strncat(buffer, id, BUFFER_LENGTH-1);
  strncat(buffer, "\":{", BUFFER_LENGTH-1);
}

static inline void __add_reference(const char* name, const char* id, bool comma){
  if(id[0]=='\0'){ // value is not set
    return;
  }
  __add_attribute(name, comma);
  strncat(buffer, "\"cf:", BUFFER_LENGTH-1);
  strncat(buffer, id, BUFFER_LENGTH-1);
  strncat(buffer, "\"", BUFFER_LENGTH-1);
}


static inline void __add_json_attribute(const char* name, const char* value, bool comma){
  __add_attribute(name, comma);
  strncat(buffer, value, BUFFER_LENGTH-1);
}

static inline void __add_label_attribute(const char* type, const char* text, bool comma){
  __add_attribute("prov:label", comma);
  if(type!=NULL){
    strncat(buffer, "\"[", BUFFER_LENGTH-1);
    strncat(buffer, type, BUFFER_LENGTH-1);
    strncat(buffer, "] ", BUFFER_LENGTH-1);
  }else{
    strncat(buffer, "\"", BUFFER_LENGTH-1);
  }
  if(text!=NULL)
    strncat(buffer, text, BUFFER_LENGTH-1);
  strncat(buffer, "\"", BUFFER_LENGTH-1);
}

static inline void __close_json_entry(char* buffer)
{
  strncat(buffer, "}", BUFFER_LENGTH-1);
}

static inline void __node_identifier(const struct node_identifier* n){
  __add_uint64_attribute("cf:id", n->id, false);
  // __add_string_attribute("prov:type", node_id_to_str(n->type), true);
  __add_uint32_attribute("cf:boot_id", n->boot_id, true);
  __add_machine_id(n->machine_id, true);
  __add_uint32_attribute("cf:version", n->version, true);
}

static inline void __node_start(const char* id,
                                const struct node_identifier* n,
                                uint64_t taint,
                                uint64_t jiffies,
                                uint8_t epoch){
  __init_json_entry(id);
  __node_identifier(n);
  __add_date_attribute(true);
  __add_uint64hex_attribute("cf:taint", taint, true);
  __add_uint64_attribute("cf:jiffies", jiffies, true);
  __add_uint32_attribute("cf:epoch", epoch, true);
}

static inline void __relation_identifier(const struct relation_identifier* e){
  __add_uint64_attribute("cf:id", e->id, false);
  // __add_string_attribute("prov:type", relation_id_to_str(e->type), true);
  __add_uint32_attribute("cf:boot_id", e->boot_id, true);
  __add_machine_id(e->machine_id, true);
}

static char* __relation_to_json(struct relation_struct* e, const char* snd, const char* rcv){
  RELATION_PREP_IDs(e);
  __init_json_entry(id);
  __relation_identifier(&(e->identifier.relation_id));
  __add_date_attribute(true);
  __add_uint64_attribute("cf:jiffies", e->jiffies, true);
  __add_uint32_attribute("cf:epoch", e->epoch, true);
  // __add_label_attribute(NULL, relation_id_to_str(e->identifier.relation_id.type), true);
  if(e->allowed==FLOW_ALLOWED)
    __add_string_attribute("cf:allowed", "true", true);
  else
    __add_string_attribute("cf:allowed", "false", true);
  __add_reference(snd, sender, true);
  __add_reference(rcv, receiver, true);
  if(e->set==FILE_INFO_SET && e->offset>0)
    __add_int64_attribute("cf:offset", e->offset, true); // just offset for now
  __add_uint64hex_attribute("cf:flags", e->flags, true);
  __add_uint64_attribute("cf:task_id", e->task_id, true);
  __close_json_entry(buffer);
  return buffer;
}

char* used_to_json(struct relation_struct* e){
  return __relation_to_json(e, "prov:entity", "prov:activity");
}

char* generated_to_json(struct relation_struct* e){
  return __relation_to_json(e, "prov:activity", "prov:entity");
}

char* informed_to_json(struct relation_struct* e){
  return __relation_to_json(e, "prov:informant", "prov:informed");
}

char* influenced_to_json(struct relation_struct* e){
  return __relation_to_json(e, "prov:influencer", "prov:influencee");
}

char* associated_to_json(struct relation_struct* e){
  return __relation_to_json(e, "prov:agent", "prov:activity");
}


char* derived_to_json(struct relation_struct* e){
  return __relation_to_json(e, "prov:usedEntity", "prov:generatedEntity");
}

char* disc_to_json(struct disc_node_struct* n){
  DISC_PREP_IDs(n);
  __node_start(id, &(n->identifier.node_id), n->taint, n->jiffies, n->epoch);
  __add_reference("cf:hasParent", parent_id, true);
  if(n->length > 0){
    strncat(buffer, ",", BUFFER_LENGTH-1);
    strncat(buffer, n->content, BUFFER_LENGTH-1);
  }
  __close_json_entry(buffer);
  return buffer;
}

char* proc_to_json(struct proc_prov_struct* n){
  char tmp[33];
  char secctx[PATH_MAX];
  // provenance_secid_to_secctx(n->secid, secctx, PATH_MAX);
  NODE_PREP_IDs(n);
  __node_start(id, &(n->identifier.node_id), n->taint, n->jiffies, n->epoch);
  __add_uint32_attribute("cf:uid", n->uid, true);
  __add_uint32_attribute("cf:gid", n->gid, true);
  __add_uint32_attribute("cf:tgid", n->tgid, true);
  __add_uint32_attribute("cf:utsns", n->utsns, true);
  __add_uint32_attribute("cf:ipcns", n->ipcns, true);
  __add_uint32_attribute("cf:mntns", n->mntns, true);
  __add_uint32_attribute("cf:pidns", n->pidns, true);
  __add_uint32_attribute("cf:netns", n->netns, true);
  __add_uint32_attribute("cf:cgroupns", n->cgroupns, true);
  __add_string_attribute("cf:secctx", secctx, true);
  snprintf(tmp, sizeof(tmp), "%u", n->identifier.node_id.version);
  __add_label_attribute("process", tmp, true);
  // __add_label_attribute("process", utoa(n->identifier.node_id.version, tmp, DECIMAL), true);
  __close_json_entry(buffer);
  return buffer;
}

char* task_to_json(struct task_prov_struct* n){
  char tmp[33];
  char secctx[PATH_MAX];
  // provenance_secid_to_secctx(n->secid, secctx, PATH_MAX);
  NODE_PREP_IDs(n);
  __node_start(id, &(n->identifier.node_id), n->taint, n->jiffies, n->epoch);
  __add_uint32_attribute("cf:pid", n->pid, true);
  __add_uint32_attribute("cf:vpid", n->vpid, true);
  __add_uint64_attribute("cf:utime", n->utime, true);
  __add_uint64_attribute("cf:stime", n->stime, true);
  __add_uint64_attribute("cf:vm", n->vm, true);
  __add_uint64_attribute("cf:rss", n->rss, true);
  __add_uint64_attribute("cf:hw_vm", n->hw_vm, true);
  __add_uint64_attribute("cf:hw_rss", n->hw_rss, true);
  __add_uint64_attribute("cf:rbytes", n->rbytes, true);
  __add_uint64_attribute("cf:wbytes", n->wbytes, true);
  __add_uint64_attribute("cf:cancel_wbytes", n->cancel_wbytes, true);
  snprintf(tmp, sizeof(tmp), "%u", n->identifier.node_id.version);
  __add_label_attribute("task", tmp, true);
  // __add_label_attribute("task", utoa(n->identifier.node_id.version, tmp, DECIMAL), true);
  __close_json_entry(buffer);
  return buffer;
}

static const char STR_UNKNOWN[]= "unknown";
static const char STR_BLOCK_SPECIAL[]= "block special";
static const char STR_CHAR_SPECIAL[]= "char special";
static const char STR_DIRECTORY[]= "directory";
static const char STR_FIFO[]= "fifo";
static const char STR_LINK[]= "link";
static const char STR_FILE[]= "file";
static const char STR_SOCKET[]= "socket";

char* inode_to_json(struct inode_prov_struct* n){
  char uuid[UUID_STR_SIZE];
  char tmp[65];
  char secctx[PATH_MAX];
  // provenance_secid_to_secctx(n->secid, secctx, PATH_MAX);
  NODE_PREP_IDs(n);
  __node_start(id, &(n->identifier.node_id), n->taint, n->jiffies, n->epoch);
  __add_uint32_attribute("cf:uid", n->uid, true);
  __add_uint32_attribute("cf:gid", n->gid, true);
  __add_uint32hex_attribute("cf:mode", n->mode, true);
  __add_string_attribute("cf:secctx", secctx, true);
  __add_uint32_attribute("cf:ino", n->ino, true);
  __add_string_attribute("cf:uuid", uuid_to_str(n->sb_uuid, uuid, UUID_STR_SIZE), true);
  snprintf(tmp, sizeof(tmp), "%u", n->identifier.node_id.version);
  // __add_label_attribute(node_id_to_str(n->identifier.node_id.type), tmp, true);
  // __add_label_attribute(node_id_to_str(n->identifier.node_id.type), utoa(n->identifier.node_id.version, tmp, DECIMAL), true);
  __close_json_entry(buffer);
  return buffer;
}

char* iattr_to_json(struct iattr_prov_struct* n){
  char tmp[65];
  NODE_PREP_IDs(n);
  __node_start(id, &(n->identifier.node_id), n->taint, n->jiffies, n->epoch);
  __add_uint32hex_attribute("cf:valid", n->valid, true);
  __add_uint32hex_attribute("cf:mode", n->mode, true);
  __add_uint32_attribute("cf:uid", n->uid, true);
  __add_uint32_attribute("cf:gid", n->gid, true);
  __add_int64_attribute("cf:size", n->size, true);
  __add_int64_attribute("cf:atime", n->atime, true);
  __add_int64_attribute("cf:ctime", n->ctime, true);
  __add_int64_attribute("cf:mtime", n->mtime, true);
  snprintf(tmp, sizeof(tmp), "%lu", n->identifier.node_id.id);
  __add_label_attribute("iattr", tmp, true);
  // __add_label_attribute("iattr", utoa(n->identifier.node_id.id, tmp, DECIMAL), true);
  __close_json_entry(buffer);
  return buffer;
}

char* xattr_to_json(struct xattr_prov_struct* n){
  NODE_PREP_IDs(n);
  __node_start(id, &(n->identifier.node_id), n->taint, n->jiffies, n->epoch);
  __add_string_attribute("cf:name", n->name, true);
  if(n->size>0){
    __add_uint32_attribute("cf:size", n->size, true);
    // TODO record value when present
  }
  __add_label_attribute("xattr", n->name, true);
  __close_json_entry(buffer);
  return buffer;
}

char* pckcnt_to_json(struct pckcnt_struct* n){
  char* cntenc;
  NODE_PREP_IDs(n);
  __node_start(id, &(n->identifier.node_id), n->taint, n->jiffies, n->epoch);
  cntenc = malloc( encode64Bound(n->length) );
  base64encode(n->content, n->length, cntenc, encode64Bound(n->length));
  __add_string_attribute("cf:content", cntenc, true);
  free(cntenc);
  __add_uint32_attribute("cf:length", n->length, true);
  if(n->truncated==PROV_TRUNCATED)
    __add_string_attribute("cf:truncated", "true", true);
  else
    __add_string_attribute("cf:truncated", "false", true);
  __add_label_attribute("content", NULL, true);
  __close_json_entry(buffer);
  return buffer;
}

char* sb_to_json(struct sb_struct* n){
  char uuid[UUID_STR_SIZE];
  NODE_PREP_IDs(n);
  __node_start(id, &(n->identifier.node_id), n->taint, n->jiffies, n->epoch);
  __add_string_attribute("cf:uuid", uuid_to_str(n->uuid, uuid, UUID_STR_SIZE), true);
  __close_json_entry(buffer);
  return buffer;
}

char* msg_to_json(struct msg_msg_struct* n){
  NODE_PREP_IDs(n);
  __node_start(id, &(n->identifier.node_id), n->taint, n->jiffies, n->epoch);
  __close_json_entry(buffer);
  return buffer;
}

char* shm_to_json(struct shm_struct* n){
  NODE_PREP_IDs(n);
  __node_start(id, &(n->identifier.node_id), n->taint, n->jiffies, n->epoch);
  __add_uint32hex_attribute("cf:mode", n->mode, true);
  __close_json_entry(buffer);
  return buffer;
}

char* packet_to_json(struct pck_struct* p){
  char tmp[256];
  PACKET_PREP_IDs(p);
  __init_json_entry(id);
  __add_uint32_attribute("cf:id", p->identifier.packet_id.id, false);
  __add_uint32_attribute("cf:seq", p->identifier.packet_id.seq, true);
  __add_ipv4_attribute("cf:sender", p->identifier.packet_id.snd_ip, p->identifier.packet_id.snd_port, true);
  __add_ipv4_attribute("cf:receiver", p->identifier.packet_id.rcv_ip, p->identifier.packet_id.rcv_port, true);
  __add_string_attribute("prov:type", "packet", true);
  __add_uint64hex_attribute("cf:taint", p->taint, true);
  __add_uint64_attribute("cf:jiffies", p->jiffies, true);
  strncat(buffer, ",\"prov:label\":\"[packet] ", BUFFER_LENGTH-1);
  __add_ipv4(p->identifier.packet_id.snd_ip, p->identifier.packet_id.snd_port);
  strncat(buffer, "->", BUFFER_LENGTH-1);
  __add_ipv4(p->identifier.packet_id.rcv_ip, p->identifier.packet_id.rcv_port);
  strncat(buffer, " (", BUFFER_LENGTH-1);
  // strncat(buffer, utoa(p->identifier.packet_id.id, tmp, DECIMAL), BUFFER_LENGTH-1);
  strncat(buffer, ")\"", BUFFER_LENGTH-1);
  __close_json_entry(buffer);
  return buffer;
}

char* str_msg_to_json(struct str_struct* n){
  int i=0;
  NODE_PREP_IDs(n);
  __node_start(id, &(n->identifier.node_id), n->taint, n->jiffies, n->epoch);
  for(i=0; i < n->length; i++){
    if(n->str[i]=='"')
      n->str[i]=' ';
    if(n->str[i]<32 || n->str[i]>125)
      n->str[i]='_';
  }
  __add_string_attribute("cf:log", n->str, true);
  __add_label_attribute("log", n->str, true);
  __close_json_entry(buffer);
  return buffer;
}

char* sockaddr_to_json(char* buf, size_t blen, struct sockaddr_storage* addr, size_t length){
  char host[NI_MAXHOST];
  char serv[NI_MAXSERV];
  int err;
  struct sockaddr *ad = (struct sockaddr*)addr;

  if(ad->sa_family == AF_INET){
    err = getnameinfo(ad, sizeof(struct sockaddr_in), host, NI_MAXHOST, serv, NI_MAXSERV, NI_NUMERICHOST | NI_NUMERICSERV);
    if (err < 0)
      snprintf(buf, blen, "{\"type\":\"AF_INET\", \"host\":\"%s\", \"service\":\"%s\", \"error\":\"%s\"}", "could not resolve", "could not resolve", gai_strerror(err));
    else
      snprintf(buf, blen, "{\"type\":\"AF_INET\", \"host\":\"%s\", \"service\":\"%s\"}", host, serv);
  }else if(ad->sa_family == AF_INET6){
    err = getnameinfo(ad, sizeof(struct sockaddr_in6), host, NI_MAXHOST, serv, NI_MAXSERV, NI_NUMERICHOST | NI_NUMERICSERV);
    if (err < 0)
      snprintf(buf, blen, "{\"type\":\"AF_INET6\", \"host\":\"%s\", \"service\":\"%s\", \"error\":\"%s\"}", "could not resolve", "could not resolve", gai_strerror(err));
    else
      snprintf(buf, blen, "{\"type\":\"AF_INET6\", \"host\":\"%s\", \"service\":\"%s\"}", host, serv);
  }else if(ad->sa_family == AF_UNIX){
    snprintf(buf, blen, "{\"type\":\"AF_UNIX\", \"path\":\"%s\"}", ((struct sockaddr_un*)addr)->sun_path);
  }else{
    err = getnameinfo(ad, length, host, NI_MAXHOST, serv, NI_MAXSERV, NI_NUMERICHOST | NI_NUMERICSERV);
    if (err < 0)
      snprintf(buf, blen, "{\"type\":%d, \"host\":\"%s\", \"service\":\"%s\", \"error\":\"%s\"}", ad->sa_family, host, serv, gai_strerror(err));
    else
      snprintf(buf, blen, "{\"type\":%d, \"host\":\"%s\", \"service\":\"%s\"}", ad->sa_family, host, serv);
  }
  return buf;
}

char* sockaddr_to_label(char* buf, size_t blen, struct sockaddr_storage* addr, size_t length){
  char host[NI_MAXHOST];
  char serv[NI_MAXSERV];
  int err;
  struct sockaddr *ad = (struct sockaddr*)addr;

  if(ad->sa_family == AF_INET){
    err = getnameinfo(ad, sizeof(struct sockaddr_in), host, NI_MAXHOST, serv, NI_MAXSERV, NI_NUMERICHOST | NI_NUMERICSERV);
    if (err < 0)
      snprintf(buf, blen, "IPV4 could not resolve (%s)", gai_strerror(err));
    else
      snprintf(buf, blen, "IPV4 %s (%s)", host, serv);
  }else if(ad->sa_family == AF_INET6){
    err = getnameinfo(ad, sizeof(struct sockaddr_in6), host, NI_MAXHOST, serv, NI_MAXSERV, NI_NUMERICHOST | NI_NUMERICSERV);
    if (err < 0)
      snprintf(buf, blen, "IPV6 could not resolve (%s)", gai_strerror(err));
    else
      snprintf(buf, blen, "IPV6 %s (%s)", host, serv);
  }else if(ad->sa_family == AF_UNIX){
    snprintf(buf, blen, "UNIX %s", ((struct sockaddr_un*)addr)->sun_path);
  }else{
    err = getnameinfo(ad, length, host, NI_MAXHOST, serv, NI_MAXSERV, NI_NUMERICHOST | NI_NUMERICSERV);
    if (err < 0)
      snprintf(buf, blen, "%d could not resolve (%s)", ad->sa_family, gai_strerror(err));
    else
      snprintf(buf, blen, "%d %s (%s)", ad->sa_family, host, serv);
  }

  return buf;
}

char* addr_to_json(struct address_struct* n){
  char addr_info[PATH_MAX+1024];
  NODE_PREP_IDs(n);
  __node_start(id, &(n->identifier.node_id), n->taint, n->jiffies, n->epoch);
  __add_json_attribute("cf:address", sockaddr_to_json(addr_info, PATH_MAX+1024, &n->addr, n->length), true);
  __add_label_attribute("address", sockaddr_to_label(addr_info, PATH_MAX+1024, &n->addr, n->length), true);
  __close_json_entry(buffer);
  return buffer;
}

char* pathname_to_json(struct file_name_struct* n){
  int i;
  NODE_PREP_IDs(n);
  __node_start(id, &(n->identifier.node_id), n->taint, n->jiffies, n->epoch);
  for(i=0; i<n->length; i++){
    if(n->name[i]=='\\')
      n->name[i]='/';
  }
  __add_string_attribute("cf:pathname", n->name, true);
  __add_label_attribute("path", n->name, true);
  __close_json_entry(buffer);
  return buffer;
}

char* arg_to_json(struct arg_struct* n){
  int i;
  char* tmp;
  NODE_PREP_IDs(n);
  __node_start(id, &(n->identifier.node_id), n->taint, n->jiffies, n->epoch);
  for(i=0; i<n->length; i++){
    if(n->value[i]=='\\')
      n->value[i]='/';
    if(n->value[i]=='\n')
      n->value[i]=' ';
    if(n->value[i]=='\t')
      n->value[i]=' ';
  }
  tmp = repl_str(n->value, "\"", "\\\"");
  if(tmp==NULL)
    tmp = n->value;
  __add_string_attribute("cf:value", tmp, true);
  if(n->truncated==PROV_TRUNCATED)
    __add_string_attribute("cf:truncated", "true", true);
  else
    __add_string_attribute("cf:truncated", "false", true);
  if(n->identifier.node_id.type == ENT_ARG)
    __add_label_attribute("argv", tmp, true);
  else
    __add_label_attribute("envp", tmp, true);
  __close_json_entry(buffer);
  if(tmp != n->value)
    free(tmp);
  return buffer;
}

char* machine_to_json(struct machine_struct* m){
  char tmp[256];
  NODE_PREP_IDs(m);
  __node_start(id, &(m->identifier.node_id), m->taint, m->jiffies, m->epoch);
  __add_string_attribute("cf:u_sysname", m->utsname.sysname, true);
  __add_string_attribute("cf:u_nodename", m->utsname.nodename, true);
  __add_string_attribute("cf:u_release", m->utsname.release, true);
  __add_string_attribute("cf:u_version", m->utsname.version, true);
  __add_string_attribute("cf:u_machine", m->utsname.machine, true);
  __add_string_attribute("cf:u_domainname", m->utsname.domainname, true);
  sprintf(tmp, "%d.%d.%d", m->cam_major, m->cam_minor, m->cam_patch);
  __add_string_attribute("cf:k_version", tmp, true);
  __add_string_attribute("cf:k_commit", m->commit, true);
  provenance_lib_version(tmp, 256);
  __add_string_attribute("cf:l_version", tmp, true);
  provenance_lib_commit(tmp, 256);
  __add_string_attribute("cf:l_commit", tmp, true);
  __close_json_entry(buffer);
  return buffer;
}
// ----------------------------------
static struct provenance_ops prov_ops;

void init( void ){
  pid_t tid = gettid();
  syslog(LOG_INFO, "Init audit thread (%d)", (int) tid);
}

void w3c_str(struct str_struct* data){
  append_entity(str_msg_to_json(data));
}

void w3c_derived(struct relation_struct* relation){
  append_derived(derived_to_json(relation));
}

void w3c_generated(struct relation_struct* relation){
  append_generated(generated_to_json(relation));
}

void w3c_used(struct relation_struct* relation){
  append_used(used_to_json(relation));
}

void w3c_informed(struct relation_struct* relation){
  append_informed(informed_to_json(relation));
}

void w3c_influenced(struct relation_struct* relation){
  append_influenced(influenced_to_json(relation));
}

void w3c_associated(struct relation_struct* relation){
  append_associated(associated_to_json(relation));
}

void w3c_proc(struct proc_prov_struct* proc){
  append_entity(proc_to_json(proc));
}

void w3c_task(struct task_prov_struct* task){
  append_activity(task_to_json(task));
}

void w3c_inode(struct inode_prov_struct* inode){
  append_entity(inode_to_json(inode));
}

void w3c_act_disc(struct disc_node_struct* node){
  append_activity(disc_to_json(node));
}

void w3c_agt_disc(struct disc_node_struct* node){
  append_agent(disc_to_json(node));
}

void w3c_ent_disc(struct disc_node_struct* node){
  append_entity(disc_to_json(node));
}

void w3c_msg(struct msg_msg_struct* msg){
  append_entity(msg_to_json(msg));
}

void w3c_shm(struct shm_struct* shm){
  append_entity(shm_to_json(shm));
}

void w3c_packet(struct pck_struct* pck){
  append_entity(packet_to_json(pck));
}

void w3c_address(struct address_struct* address){
  append_entity(addr_to_json(address));
}

void w3c_file_name(struct file_name_struct* f_name){
  append_entity(pathname_to_json(f_name));
}

void w3c_iattr(struct iattr_prov_struct* iattr){
  append_entity(iattr_to_json(iattr));
}


void w3c_xattr(struct xattr_prov_struct* xattr){
  append_entity(xattr_to_json(xattr));
}

void w3c_packet_content(struct pckcnt_struct* cnt){
  append_entity(pckcnt_to_json(cnt));
}

void w3c_arg(struct arg_struct* arg){
  append_entity(arg_to_json(arg));
}

void w3c_machine(struct machine_struct* machine){
  append_agent(machine_to_json(machine));
}

void log_error(char* error){
  syslog(LOG_ERR, "From library: %s", error);
}

struct provenance_ops ops_null = {
  .init=&init,
  .log_derived=NULL,
  .log_generated=NULL,
  .log_used=NULL,
  .log_informed=NULL,
  .log_influenced=NULL,
  .log_associated=NULL,
  .log_proc=NULL,
  .log_task=NULL,
  .log_inode=NULL,
  .log_str=NULL,
  .log_act_disc=NULL,
  .log_agt_disc=NULL,
  .log_ent_disc=NULL,
  .log_msg=NULL,
  .log_shm=NULL,
  .log_packet=NULL,
  .log_address=NULL,
  .log_file_name=NULL,
  .log_iattr=NULL,
  .log_xattr=NULL,
  .log_packet_content=NULL,
  .log_arg=NULL,
  .log_machine=NULL,
  .log_error=&log_error
};

struct provenance_ops w3c_ops = {
  .init=&init,
  .log_derived=&w3c_derived,
  .log_generated=&w3c_generated,
  .log_used=&w3c_used,
  .log_informed=&w3c_informed,
  .log_influenced=&w3c_influenced,
  .log_associated=&w3c_associated,
  .log_proc=&w3c_proc,
  .log_task=&w3c_task,
  .log_inode=&w3c_inode,
  .log_str=&w3c_str,
  .log_act_disc=&w3c_act_disc,
  .log_agt_disc=&w3c_agt_disc,
  .log_ent_disc=&w3c_ent_disc,
  .log_msg=&w3c_msg,
  .log_shm=&w3c_shm,
  .log_packet=&w3c_packet,
  .log_address=&w3c_address,
  .log_file_name=&w3c_file_name,
  .log_iattr=&w3c_iattr,
  .log_xattr=&w3c_xattr,
  .log_packet_content=&w3c_packet_content,
  .log_arg=&w3c_arg,
  .log_machine=&w3c_machine,
  .log_error=&log_error
};

void relation_record(union prov_elt *msg){
  uint64_t type = prov_type(msg);

  if(prov_is_used(type) &&  prov_ops.log_used!=NULL)
    prov_ops.log_used(&(msg->relation_info));
  else if(prov_is_informed(type) && prov_ops.log_informed!=NULL)
    prov_ops.log_informed(&(msg->relation_info));
  else if(prov_is_generated(type) && prov_ops.log_generated!=NULL)
    prov_ops.log_generated(&(msg->relation_info));
  else if(prov_is_derived(type) && prov_ops.log_derived!=NULL)
    prov_ops.log_derived(&(msg->relation_info));
  else if(prov_is_influenced(type) && prov_ops.log_influenced!=NULL)
    prov_ops.log_influenced(&(msg->relation_info));
  else if(prov_is_associated(type) && prov_ops.log_associated!=NULL)
    prov_ops.log_associated(&(msg->relation_info));
  else
    printf("Error: unknown relation type %" PRIu64 "\n", prov_type(msg));
}

void node_record(union prov_elt *msg){
  switch(prov_type(msg)){
    case ENT_PROC:
      if(prov_ops.log_proc!=NULL)
        prov_ops.log_proc(&(msg->proc_info));
      break;
    case ACT_TASK:
      if(prov_ops.log_task!=NULL)
        prov_ops.log_task(&(msg->task_info));
      break;
    case ENT_INODE_UNKNOWN:
    case ENT_INODE_LINK:
    case ENT_INODE_FILE:
    case ENT_INODE_DIRECTORY:
    case ENT_INODE_CHAR:
    case ENT_INODE_BLOCK:
    case ENT_INODE_PIPE:
    case ENT_INODE_SOCKET:
      if(prov_ops.log_inode!=NULL)
        prov_ops.log_inode(&(msg->inode_info));
      break;
    case ENT_MSG:
      if(prov_ops.log_msg!=NULL)
        prov_ops.log_msg(&(msg->msg_msg_info));
      break;
    case ENT_SHM:
      if(prov_ops.log_shm!=NULL)
        prov_ops.log_shm(&(msg->shm_info));
      break;
    case ENT_PACKET:
      if(prov_ops.log_packet!=NULL)
        prov_ops.log_packet(&(msg->pck_info));
      break;
    case ENT_IATTR:
      if(prov_ops.log_iattr!=NULL)
        prov_ops.log_iattr(&(msg->iattr_info));
      break;
    default:
      printf("Error: unknown node type %" PRIu64 "\n", prov_type(msg));
      break;
  }
}

void prov_init() {
  // memcpy(&prov_ops, &ops_null, sizeof(struct provenance_ops));
  memcpy(&prov_ops, &w3c_ops, sizeof(struct provenance_ops));
}

void prov_record(union prov_elt* msg){
    /* TODO: CODE HERE
     * Record provenance in user space.
     * Follow the logic here:
     * https://github.com/CamFlow/libprovenance/blob/master/src/relay.c#L268
    */

    if (prov_is_relation(msg)) {
      relation_record(msg);
      printf("Relation provenance recorded\n");
    } else {
      node_record(msg);
      printf("Node provenance recorded\n");
    }
}
