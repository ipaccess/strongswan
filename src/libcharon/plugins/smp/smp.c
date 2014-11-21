/*
 * Copyright (C) 2007 Martin Willi
 * Hochschule fuer Technik Rapperswil
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the
 * Free Software Foundation; either version 2 of the License, or (at your
 * option) any later version.  See <http://www.fsf.org/copyleft/gpl.txt>.
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY
 * or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License
 * for more details.
 */

#include <stdlib.h>

#include "smp.h"

#include <sys/types.h>
#include <sys/stat.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>
#include <errno.h>
#include <signal.h>
#include <libxml/xmlreader.h>
#include <libxml/xmlwriter.h>

#include <library.h>
#include <daemon.h>
#include <threading/thread.h>
#include <processing/jobs/callback_job.h>

#if 1

/**
 * maximum number of smp messages we expect to receive in
 * a single read from the socket (never actually seen more
 * than two).
 */
#define SMP_MAX_MSGS_PER_BUFFER 16


/**
 * maximum time, in seconds, to wait for a response to a
 * fetch request.
 *
 * the fetch tends to happen when one of the child_sa pair
 * has been installed in the kernel. If it blocks in this
 * state for more than 10s a kernel timer expires and we get
 * a XFRM_MSG_EXPIRE for that sa, so keep this timer short.
 */
#define FETCH_RESPONSE_TIMEOUT  5 


#endif

typedef struct private_smp_t private_smp_t;

/**
 * Private data of an smp_t object.
 */
struct private_smp_t {

	/**
	 * Public part of smp_t object.
	 */
	smp_t public;

	/**
	 * XML unix socket fd
	 */
	int socket;
	/**
	 * event listener
	 */
	listener_t *listener;

};

#if 1
/**
 * Create a listener instance.
 */
listener_t *smp_listener_create();

/**
 * responses received for clients
 */
typedef struct {
	unsigned long id;
	char *msg;
} smp_response;

typedef struct {
	xmlTextReaderPtr reader;
	char *id;
	char *buffer;
} smp_request;

/**
 * connected clients
 */
typedef struct {
	int fd;
	unsigned long request_id;
	linked_list_t *responses;  /* Change/read only while holding readMutex */
	linked_list_t *requests;   /* Change/read only while holding readMutex */
	int activeReader;          /* Change/read only while holding readMutex */
	pthread_mutex_t readMutex;
	pthread_cond_t  readCond;
} smp_client;

/**
 * list of currently connected SMP clients
 */
static linked_list_t *smp_clients = NULL;

static char *fetch_uri(smp_client *client, char *uri);
static void process_buffer(int fd, char *buffer, size_t len);
static void close_client(smp_client *client);

#endif
ENUM(ike_sa_state_lower_names, IKE_CREATED, IKE_DESTROYING,
	"created",
	"connecting",
	"established",
	"passive",
	"rekeying",
	"deleting",
	"destroying"
);

typedef struct smp_fetcher_t smp_fetcher_t;

/**
 * Fetcher implementation
 */
struct smp_fetcher_t {

	/**
	 * Implements fetcher interface
	 */
	fetcher_t interface;
		
	/**
     * Destroy a smp_fetcher instance.
     */
    void (*destroy)(smp_fetcher_t *this);
};

typedef struct private_smp_fetcher_t private_smp_fetcher_t;

/**
 * private data of a smp_fetcher_t object.
 */
struct private_smp_fetcher_t {
	/**
	 * Public data
	 */
	smp_fetcher_t public;

	/**
	 * request type, as set with FETCH_REQUEST_TYPE
	 */
	char *request_type;
};

/**
 * callback used by linked list functions to find and SMP
 * response by its id
 */
static bool find_response_by_id(smp_response *current, unsigned long id)
{
	return (current->id == id);
}

/**
 * find and SMP response by its id
 */
static smp_response *find_response(linked_list_t *responses, unsigned long id)
{
	smp_response *response = NULL;
	if (responses->find_first(responses, 
					(linked_list_match_t)find_response_by_id,
					(void**)&response, id) == SUCCESS)
	{
		return response;
	}
	return NULL;
}

/**
 * callback used by linked list functions to find and SMP
 * client by its fd
 */
static bool find_client(smp_client *current, int fd)
{
	return (current->fd == fd);
}

/**
 * retrieve an SMP client by its fd
 */
static smp_client *get_client(int fd)
{
	smp_client *client = NULL;
	if (smp_clients->find_first(smp_clients,
					(linked_list_match_t)find_client,
					(void**)&client, fd) == SUCCESS)
	{
		return client;
	}
	return NULL;
}

/** 
 * add an SMP client to the client list
 */
static smp_client *add_client(int fd)
{
	smp_client *client = get_client(fd);
	
	if (!client)
	{
		DBG1(DBG_CFG, "   smp: add client %d", fd);	
		client = malloc_thing(smp_client);
		client->fd = fd;
		client->request_id = 0;
		client->responses = linked_list_create();
		client->requests = linked_list_create();
		client->activeReader = 0;
		
		pthread_cond_init(&client->readCond, NULL);
		pthread_mutex_init(&client->readMutex, NULL);


		smp_clients->insert_last(smp_clients, client);
	}
	
	return client;
}

/**
 * removes smp client from client list
 */
static void remove_client(int fd)
{
	smp_client *client;
	smp_response *response;
	smp_request *req;
	
	DBG1(DBG_CFG, "   smp: remove client %d", fd);
	
	if ((client = get_client(fd)) != NULL)
	{    
		while (client->responses->remove_last(client->responses,
							(void**)&response) == SUCCESS)
		{
			free(response->msg);
			free(response);
		}
		
		client->responses->destroy(client->responses);
		while (client->requests->remove_last(client->requests,
							(void**)&req) == SUCCESS)
		{
			free(req->id);
			xmlFreeTextReader(req->reader);
			free(req->buffer);
			free(req);
		}
		
		client->requests->destroy(client->requests);
		smp_clients->remove(smp_clients, client, NULL);
		free(client);
	}
}

static status_t get_response_from_file(const char *fname, chunk_t *result)
{
	status_t status = FAILED;
	struct stat fstat;
	int n = 0, c;
	
	if (stat(fname, &fstat) == 0)
	{
		chunk_t raw_chunk;
		raw_chunk.len = fstat.st_size;
		raw_chunk.ptr = malloc(raw_chunk.len);
		FILE *fp = fopen(fname, "r");  
		if (fp && raw_chunk.ptr)
		{
			n = 0;
			while (n < raw_chunk.len)
			{
				if ((c = fgetc(fp)) == EOF)
					break;
				raw_chunk.ptr[n++] = c;
			}
			if (n == raw_chunk.len)
			{
				status = SUCCESS;
				*result = chunk_clone(raw_chunk);
				DBG1(DBG_CFG, "   smp: read %d bytes from CRL file", n);
			}
			else
			{
				DBG1(DBG_CFG, "   smp: read short! (expected %d got %d)",
					raw_chunk.len, n);
			}
			fclose(fp);
		}
	}
	
	return status;
}

/**
 * Implements fetcher_t.fetch.
 */
static status_t fetch(private_smp_fetcher_t *this, char *uri, chunk_t *result)
{
	status_t status = FAILED;
	*result = chunk_empty;
#if 1
	smp_client *client;
	char *filepath = NULL;
	
	/* TODO: what if there are multiple clients? */
	if (smp_clients->get_last(smp_clients, (void**)&client) == SUCCESS)
	{
		filepath = fetch_uri(client, uri);
		
		if (!filepath)
		{
			DBG1(DBG_CFG, "   smp: no response");
		}
		else
		{
			if (filepath[0] == '\0')
			{
				DBG1(DBG_CFG, "   smp: got failure response");
			}
			else
			{   
				status = get_response_from_file(filepath, result);
			}
			
			free(filepath);
		}
	}
	else
	{
		DBG1(DBG_CFG, "   smp: no fetcher clients available");
		status = NOT_SUPPORTED;
	}

	return status;
}

/**
 * Implementation of fetcher_t.set_option.
 */
static bool set_option(private_smp_fetcher_t *this, fetcher_option_t option, ...)
{
	/* no options supported */
}

/**
 * Implements fetcher_t.destroy
 */
static void destroy_fetcher(private_smp_fetcher_t *this)
{
	free(this);
}

/**
 * Described in header.
 */
smp_fetcher_t *smp_fetcher_create()
{
	private_smp_fetcher_t *this = malloc_thing(private_smp_fetcher_t);

	this->request_type = NULL;

	this->public.interface.fetch = (status_t(*)(fetcher_t*,char*,chunk_t*))fetch;
	this->public.interface.set_option = (bool(*)(fetcher_t*, fetcher_option_t option, ...))set_option;
	this->public.interface.destroy = (void (*)(fetcher_t*))destroy_fetcher;

	return &this->public;
}

#endif
/**
 * write a bool into element
 */
static void write_bool(xmlTextWriterPtr writer, char *element, bool val)
{
	xmlTextWriterWriteElement(writer, element, val ? "true" : "false");
}

/**
 * write a identification_t into element
 */
static void write_id(xmlTextWriterPtr writer, char *element, identification_t *id)
{
	xmlTextWriterStartElement(writer, element);
	switch (id->get_type(id))
	{
		{
			char *type = "";
			while (TRUE)
			{
				case ID_ANY:
					type = "any";
					break;
				case ID_IPV4_ADDR:
					type = "ipv4";
					break;
				case ID_IPV6_ADDR:
					type = "ipv6";
					break;
				case ID_FQDN:
					type = "fqdn";
					break;
				case ID_RFC822_ADDR:
					type = "email";
					break;
				case ID_DER_ASN1_DN:
					type = "asn1dn";
					break;
				case ID_DER_ASN1_GN:
					type = "asn1gn";
					break;
			}
			xmlTextWriterWriteAttribute(writer, "type", type);
			xmlTextWriterWriteFormatString(writer, "%Y", id);
			break;
		}
		default:
			/* TODO: base64 keyid */
			xmlTextWriterWriteAttribute(writer, "type", "keyid");
			break;
	}
	xmlTextWriterEndElement(writer);
}

/**
 * write a host_t address into an element
 */
static void write_address(xmlTextWriterPtr writer, char *element, host_t *host)
{
	xmlTextWriterStartElement(writer, element);
	xmlTextWriterWriteAttribute(writer, "type",
						host->get_family(host) == AF_INET ? "ipv4" : "ipv6");
	if (host->is_anyaddr(host))
	{	/* do not use %any for XML */
		xmlTextWriterWriteFormatString(writer, "%s",
						host->get_family(host) == AF_INET ? "0.0.0.0" : "::");
	}
	else
	{
		xmlTextWriterWriteFormatString(writer, "%H", host);
	}
	xmlTextWriterEndElement(writer);
}

/**
 * write networks element
 */
static void write_networks(xmlTextWriterPtr writer, char *element,
						   linked_list_t *list)
{
	enumerator_t *enumerator;
	traffic_selector_t *ts;

	xmlTextWriterStartElement(writer, element);
	enumerator = list->create_enumerator(list);
	while (enumerator->enumerate(enumerator, (void**)&ts))
	{
		xmlTextWriterStartElement(writer, "network");
		xmlTextWriterWriteAttribute(writer, "type",
						ts->get_type(ts) == TS_IPV4_ADDR_RANGE ? "ipv4" : "ipv6");
		xmlTextWriterWriteFormatString(writer, "%R", ts);
		xmlTextWriterEndElement(writer);
	}
	enumerator->destroy(enumerator);
	xmlTextWriterEndElement(writer);
}

/**
 * write a childEnd
 */
static void write_childend(xmlTextWriterPtr writer, child_sa_t *child, bool local)
{
	linked_list_t *list;

	xmlTextWriterWriteFormatElement(writer, "spi", "%x",
									htonl(child->get_spi(child, local)));
	list = linked_list_create_from_enumerator(
									child->create_ts_enumerator(child, local));
	write_networks(writer, "networks", list);
	list->destroy(list);
}

/**
 * write a child_sa_t
 */
static void write_child(xmlTextWriterPtr writer, child_sa_t *child)
{
	child_cfg_t *config;

	config = child->get_config(child);

	xmlTextWriterStartElement(writer, "childsa");
	xmlTextWriterWriteFormatElement(writer, "reqid", "%d",
									child->get_reqid(child));
#if 0
	xmlTextWriterWriteFormatElement(writer, "status", "%N",
					child_sa_state_names, child->get_state(child));
#endif

	xmlTextWriterWriteFormatElement(writer, "childconfig", "%s",
									config->get_name(config));
	xmlTextWriterStartElement(writer, "local");
	write_childend(writer, child, TRUE);
	xmlTextWriterEndElement(writer);
	xmlTextWriterStartElement(writer, "remote");
	write_childend(writer, child, FALSE);
	xmlTextWriterEndElement(writer);
	xmlTextWriterEndElement(writer);
}
#if 0
/**
 * write out the dns server list
 */
static void write_dns_servers(xmlTextWriterPtr writer, ike_sa_t *ike_sa)
{
	linked_list_t *list;
	enumerator_t *enumerator;
	host_t *dns;
	int c = 0;
	
	list = ike_sa->get_dns_servers(ike_sa);
	
	xmlTextWriterStartElement(writer, "dns");
	
	enumerator = list->create_enumerator(list);
	while (enumerator->enumerate(enumerator, (void**)&dns))
	{
		xmlTextWriterWriteFormatString(writer, "%s%H", c!=0?",":"", dns);
		c++;
	}
	enumerator->destroy(enumerator);
	list->destroy_offset(list, offsetof(host_t, destroy));
	
	xmlTextWriterEndElement(writer);    
}
#endif

/**
 * process a ikesalist query request message
 */
static void request_query_ikesa(xmlTextReaderPtr reader, xmlTextWriterPtr writer)
{
	enumerator_t *enumerator;
	ike_sa_t *ike_sa;

	/* <ikesalist> */
	xmlTextWriterStartElement(writer, "ikesalist");

	enumerator = charon->controller->create_ike_sa_enumerator(
													charon->controller, TRUE);
	while (enumerator->enumerate(enumerator, &ike_sa))
	{
		ike_sa_id_t *id;
		host_t *local, *remote;
		enumerator_t *children;
		child_sa_t *child_sa;

		id = ike_sa->get_id(ike_sa);

		xmlTextWriterStartElement(writer, "ikesa");
		xmlTextWriterWriteFormatElement(writer, "id", "%d",
							ike_sa->get_unique_id(ike_sa));
		xmlTextWriterWriteFormatElement(writer, "status", "%N",
							ike_sa_state_lower_names, ike_sa->get_state(ike_sa));
		xmlTextWriterWriteElement(writer, "role",
							id->is_initiator(id) ? "initiator" : "responder");
		xmlTextWriterWriteElement(writer, "peerconfig", ike_sa->get_name(ike_sa));
#if 0
		write_dns_servers(writer, ike_sa);
#endif

		/* <local> */
		local = ike_sa->get_my_host(ike_sa);
		xmlTextWriterStartElement(writer, "local");
		xmlTextWriterWriteFormatElement(writer, "spi", "%.16llx",
							id->is_initiator(id) ? id->get_initiator_spi(id)
												 : id->get_responder_spi(id));
		write_id(writer, "identification", ike_sa->get_my_id(ike_sa));
		write_address(writer, "address", local);
		xmlTextWriterWriteFormatElement(writer, "port", "%d",
							local->get_port(local));
		if (ike_sa->supports_extension(ike_sa, EXT_NATT))
		{
			write_bool(writer, "nat", ike_sa->has_condition(ike_sa, COND_NAT_HERE));
		}
		xmlTextWriterEndElement(writer);
		/* </local> */

		/* <remote> */
		remote = ike_sa->get_other_host(ike_sa);
		xmlTextWriterStartElement(writer, "remote");
		xmlTextWriterWriteFormatElement(writer, "spi", "%.16llx",
							id->is_initiator(id) ? id->get_responder_spi(id)
												 : id->get_initiator_spi(id));
		write_id(writer, "identification", ike_sa->get_other_id(ike_sa));
		write_address(writer, "address", remote);
		xmlTextWriterWriteFormatElement(writer, "port", "%d",
							remote->get_port(remote));
		if (ike_sa->supports_extension(ike_sa, EXT_NATT))
		{
			write_bool(writer, "nat", ike_sa->has_condition(ike_sa, COND_NAT_THERE));
		}
		xmlTextWriterEndElement(writer);
		/* </remote> */

		/* <childsalist> */
		xmlTextWriterStartElement(writer, "childsalist");
		children = ike_sa->create_child_sa_enumerator(ike_sa);
		while (children->enumerate(children, (void**)&child_sa))
		{
			write_child(writer, child_sa);
		}
		children->destroy(children);
		/* </childsalist> */
		xmlTextWriterEndElement(writer);

		/* </ikesa> */
		xmlTextWriterEndElement(writer);
	}
	enumerator->destroy(enumerator);

	/* </ikesalist> */
	xmlTextWriterEndElement(writer);
}

/**
 * process a configlist query request message
 */
static void request_query_config(xmlTextReaderPtr reader, xmlTextWriterPtr writer)
{
	enumerator_t *enumerator;
	peer_cfg_t *peer_cfg;

	/* <configlist> */
	xmlTextWriterStartElement(writer, "configlist");

	enumerator = charon->backends->create_peer_cfg_enumerator(charon->backends,
											NULL, NULL, NULL, NULL, IKE_ANY);
	while (enumerator->enumerate(enumerator, &peer_cfg))
	{
		enumerator_t *children;
		child_cfg_t *child_cfg;
		ike_cfg_t *ike_cfg;
		linked_list_t *list;

		/* <peerconfig> */
		xmlTextWriterStartElement(writer, "peerconfig");
		xmlTextWriterWriteElement(writer, "name", peer_cfg->get_name(peer_cfg));

		/* TODO: write auth_cfgs */

		/* <ikeconfig> */
		ike_cfg = peer_cfg->get_ike_cfg(peer_cfg);
		xmlTextWriterStartElement(writer, "ikeconfig");
		xmlTextWriterWriteElement(writer, "local",
								  ike_cfg->get_my_addr(ike_cfg));
		xmlTextWriterWriteElement(writer, "remote",
								  ike_cfg->get_other_addr(ike_cfg));
		xmlTextWriterEndElement(writer);
		/* </ikeconfig> */

		/* <childconfiglist> */
		xmlTextWriterStartElement(writer, "childconfiglist");
		children = peer_cfg->create_child_cfg_enumerator(peer_cfg);
		while (children->enumerate(children, &child_cfg))
		{
			/* <childconfig> */
			xmlTextWriterStartElement(writer, "childconfig");
			xmlTextWriterWriteElement(writer, "name",
									  child_cfg->get_name(child_cfg));
			list = child_cfg->get_traffic_selectors(child_cfg, TRUE, NULL, NULL);
			write_networks(writer, "local", list);
			list->destroy_offset(list, offsetof(traffic_selector_t, destroy));
			list = child_cfg->get_traffic_selectors(child_cfg, FALSE, NULL, NULL);
			write_networks(writer, "remote", list);
			list->destroy_offset(list, offsetof(traffic_selector_t, destroy));
			xmlTextWriterEndElement(writer);
			/* </childconfig> */
		}
		children->destroy(children);
		/* </childconfiglist> */
		xmlTextWriterEndElement(writer);
		/* </peerconfig> */
		xmlTextWriterEndElement(writer);
	}
	enumerator->destroy(enumerator);
	/* </configlist> */
	xmlTextWriterEndElement(writer);
}

/**
 * callback which logs to a XML writer
 */
static bool xml_callback(xmlTextWriterPtr writer, debug_t group, level_t level,
						 ike_sa_t* ike_sa, char* message)
{
/* don't bother reporting the logs in SMP response, it generates
 * very large response messages. We're only really interested in
 * the status anyway. */
#if WANT_INFO_IN_LOGS
	if (level <= 1)
	{
		/* <item> */
		xmlTextWriterStartElement(writer, "item");
		xmlTextWriterWriteFormatAttribute(writer, "level", "%d", level);
		xmlTextWriterWriteFormatAttribute(writer, "source", "%N", debug_names, group);
		xmlTextWriterWriteFormatAttribute(writer, "thread", "%u", thread_current_id());
		xmlTextWriterWriteString(writer, message);
		xmlTextWriterEndElement(writer);
		/* </item> */
	}
#endif
	return TRUE;
}

/**
 * process a *terminate control request message
 */
static void request_control_terminate(xmlTextReaderPtr reader,
									  xmlTextWriterPtr writer, bool ike)
{
	if (xmlTextReaderRead(reader) == 1 &&
		xmlTextReaderNodeType(reader) == XML_READER_TYPE_TEXT)
	{
		const char *str;
		u_int32_t id;
		status_t status;

		str = xmlTextReaderConstValue(reader);
		if (str == NULL)
		{
			DBG1(DBG_CFG, "error parsing XML id string");
			return;
		}
		id = atoi(str);
		if (!id)
		{
			enumerator_t *enumerator;
			ike_sa_t *ike_sa;

			enumerator = charon->controller->create_ike_sa_enumerator(
													charon->controller, TRUE);
			while (enumerator->enumerate(enumerator, &ike_sa))
			{
				if (streq(str, ike_sa->get_name(ike_sa)))
				{
					ike = TRUE;
					id = ike_sa->get_unique_id(ike_sa);
					break;
				}
			}
			enumerator->destroy(enumerator);
		}
		if (!id)
		{
			/* remove this warning, it probably just means we attempted to 
			 * terminate an SA by name but there was no matching SA (i.e. 
			 * it was already terminated)
			DBG1(DBG_CFG, "error parsing XML id string");
			*/
			return;
		}

		DBG1(DBG_CFG, "terminating %s_SA %d", ike ? "IKE" : "CHILD", id);

		/* <log> */
		xmlTextWriterStartElement(writer, "log");
		if (ike)
		{
			status = charon->controller->terminate_ike(
					charon->controller, id,
					(controller_cb_t)xml_callback, writer, 0);
		}
		else
		{
			status = charon->controller->terminate_child(
					charon->controller, id,
					(controller_cb_t)xml_callback, writer, 0);
		}
		/* </log> */
		xmlTextWriterEndElement(writer);
		xmlTextWriterWriteFormatElement(writer, "status", "%d", status);
	}
}

/**
 * process a *initiate control request message
 */
static void request_control_initiate(xmlTextReaderPtr reader,
									  xmlTextWriterPtr writer, bool ike)
{
	if (xmlTextReaderRead(reader) == 1 &&
		xmlTextReaderNodeType(reader) == XML_READER_TYPE_TEXT)
	{
		const char *str;
		status_t status = FAILED;
		peer_cfg_t *peer;
		child_cfg_t *child = NULL;
		enumerator_t *enumerator;

		str = xmlTextReaderConstValue(reader);
		if (str == NULL)
		{
			DBG1(DBG_CFG, "error parsing XML config name string");
			return;
		}
		DBG1(DBG_CFG, "initiating %s_SA %s", ike ? "IKE" : "CHILD", str);

		/* <log> */
		xmlTextWriterStartElement(writer, "log");
		peer = charon->backends->get_peer_cfg_by_name(charon->backends,
													  (char*)str);
		if (peer)
		{
			enumerator = peer->create_child_cfg_enumerator(peer);
			if (ike)
			{
				if (enumerator->enumerate(enumerator, &child))
				{
					child->get_ref(child);
				}
				else
				{
					child = NULL;
				}
			}
			else
			{
				while (enumerator->enumerate(enumerator, &child))
				{
					if (streq(child->get_name(child), str))
					{
						child->get_ref(child);
						break;
					}
					child = NULL;
				}
			}
			enumerator->destroy(enumerator);
			if (child)
			{
				status = charon->controller->initiate(charon->controller,
							peer, child, (controller_cb_t)xml_callback,
							writer, 0);
			}
			else
			{
				peer->destroy(peer);
			}
		}
		/* </log> */
		xmlTextWriterEndElement(writer);
		xmlTextWriterWriteFormatElement(writer, "status", "%d", status);
	}
}

/**
 * process a query request
 */
static void request_query(xmlTextReaderPtr reader, xmlTextWriterPtr writer)
{
	/* <query> */
	xmlTextWriterStartElement(writer, "query");
	while (xmlTextReaderRead(reader))
	{
		if (xmlTextReaderNodeType(reader) == XML_READER_TYPE_ELEMENT)
		{
			if (streq(xmlTextReaderConstName(reader), "ikesalist"))
			{
				request_query_ikesa(reader, writer);
				break;
			}
			if (streq(xmlTextReaderConstName(reader), "configlist"))
			{
				request_query_config(reader, writer);
				break;
			}
		}
	}
	/* </query> */
	xmlTextWriterEndElement(writer);
}

/**
 * process a control request
 */
static void request_control(xmlTextReaderPtr reader, xmlTextWriterPtr writer)
{
	/* <control> */
	xmlTextWriterStartElement(writer, "control");
	while (xmlTextReaderRead(reader) == 1)
	{
		if (xmlTextReaderNodeType(reader) == XML_READER_TYPE_ELEMENT)
		{
			if (streq(xmlTextReaderConstName(reader), "ikesaterminate"))
			{
				request_control_terminate(reader, writer, TRUE);
				break;
			}
			if (streq(xmlTextReaderConstName(reader), "childsaterminate"))
			{
				request_control_terminate(reader, writer, FALSE);
				break;
			}
			if (streq(xmlTextReaderConstName(reader), "ikesainitiate"))
			{
				request_control_initiate(reader, writer, TRUE);
				break;
			}
			if (streq(xmlTextReaderConstName(reader), "childsainitiate"))
			{
				request_control_initiate(reader, writer, FALSE);
				break;
			}
		}
	}
	/* </control> */
	xmlTextWriterEndElement(writer);
}
#if 1
/**
 * put a request at the end of the list of requests to be processed
 */
static int queue_request(char* buffer, xmlTextReaderPtr reader, char *id, int fd)
{
	smp_client *client;
	
	if ((client = get_client(fd)) != NULL)
	{
		smp_request *request = malloc_thing(smp_request);
		request->buffer = buffer;
		request->reader = reader;
		request->id = strdup(id);
		client->requests->insert_last(client->requests, request);
		return 1;
	}

	return 0;
}
#endif
/**
 * process a request message
 */
static void request(xmlTextReaderPtr reader, char *id, int fd)
{
	xmlTextWriterPtr writer;

	writer = xmlNewTextWriter(xmlOutputBufferCreateFd(fd, NULL));
	if (writer == NULL)
	{
		DBG1(DBG_CFG, "opening SMP XML writer failed");
		return;
	}

	xmlTextWriterStartDocument(writer, NULL, NULL, NULL);
	/* <message xmlns="http://www.strongswan.org/smp/1.0"
		id="id" type="response"> */
	xmlTextWriterStartElement(writer, "message");
	xmlTextWriterWriteAttribute(writer, "xmlns",
								"http://www.strongswan.org/smp/1.0");
	xmlTextWriterWriteAttribute(writer, "id", id);
	xmlTextWriterWriteAttribute(writer, "type", "response");

	while (xmlTextReaderRead(reader) == 1)
	{
		if (xmlTextReaderNodeType(reader) == XML_READER_TYPE_ELEMENT)
		{
			if (streq(xmlTextReaderConstName(reader), "query"))
			{
				request_query(reader, writer);
				break;
			}
			if (streq(xmlTextReaderConstName(reader), "control"))
			{
				request_control(reader, writer);
				break;
			}
		}
	}
	/*   </message> and close document */
	xmlTextWriterEndDocument(writer);
	xmlFreeTextWriter(writer);
}
#if 1 
/**
 * process a response to a fetch request
 */
static void response_fetch(xmlTextReaderPtr reader, char *id, int fd)
{
	smp_client *client;
	smp_response *response;
	char *msg = NULL;
	
	if ((client = get_client(fd)) != NULL)
	{
		while (xmlTextReaderRead(reader) == 1)
		{
			if (xmlTextReaderNodeType(reader) == XML_READER_TYPE_ELEMENT &&
				strcmp((const char*)xmlTextReaderConstName(reader), "crl") == 0)
			{
				msg = (char*)xmlTextReaderGetAttribute(reader, (unsigned char*)"file");
				break;
			}
		}
		
		if (msg)
		{
			response = malloc_thing(smp_response);
			response->msg = malloc(strlen(msg)+1);
			strcpy(response->msg, msg);
			response->id = atoi(id);
			client->responses->insert_last(client->responses, response);
			DBG1(DBG_CFG, "   smp: got response_fetch");
		}
	}
}

/**
 * process a response message
 */
static void response(xmlTextReaderPtr reader, char *id, int fd)
{
	while (xmlTextReaderRead(reader)==1)
	{
		if (xmlTextReaderNodeType(reader) == XML_READER_TYPE_ELEMENT)
		{
			if (streq(xmlTextReaderConstName(reader), "fetch"))
			{
				response_fetch(reader, id, fd);
				break;
			}
		}
	}
}

/**
 * find a response in the client's response list.  We must hold the mutex on entry.
 */
static smp_response *get_response_from_queue(smp_client *client, unsigned long id)
{
	smp_response *response = NULL;
	
	response = find_response(client->responses, id);

	if (response)
	{
		client->responses->remove(client->responses, response, NULL);
	}
	
	return response;
}

/**
 * Return 1 if the deadline has not expired.  Calculate the time remaining if not.
 */
static int time_remaining(struct timeval *deadline, struct timeval *remaining)
{
	int retval = 0;
	
	struct timeval now;
	
	if (gettimeofday(&now, NULL) == 0)
	{
		long int secs = deadline->tv_sec - now.tv_sec;
		
		if (secs > 0)
		{
			if (deadline->tv_usec >= now.tv_usec)
			{
				remaining->tv_sec  = secs;
				remaining->tv_usec = deadline->tv_usec - now.tv_usec;
			}
			else
			{
				remaining->tv_sec  = secs - 1;
				remaining->tv_usec = 1000000 + deadline->tv_usec - now.tv_usec;
			}
			
			retval = 1;
		}
		else if ((secs == 0) && (deadline->tv_usec > now.tv_usec))
		{
			remaining->tv_sec  = 0;
			remaining->tv_usec = deadline->tv_usec - now.tv_usec;
			
			retval = 1;
		}
	}
	
	return retval;
}


/**
 * read from socket and wait for a response for specified message id for a given time limit
 */
static smp_response *wait_for_response(smp_client *client, unsigned long id, int timeout)
{
	smp_response   *response = NULL;
	struct timeval  deadline;
	struct timeval  remaining;
	struct timespec waitDeadline;
	
	/* Work out the deadline for this response */
	if (gettimeofday(&deadline, NULL))
	{
		return response;
	}
	deadline.tv_sec += timeout;

	for(;;)
	{
		struct timespec  now;
		int              still_time;

		/* We need to hold the mutex while we check or modify the queues */
		pthread_mutex_lock(&client->readMutex);

		response = get_response_from_queue(client, id);
		still_time = time_remaining(&deadline, &remaining);

		while (client->activeReader && (response == NULL) && still_time)
		{
			/* Some other thread is reading, there's nothing already queued for us
			 * to read and we've still got time.  Just wait for a while for something
			 * to change.
			 *
			 * Note that pthread_cond_timedwait takes an absolute time as a deadline
			 */
			struct timespec waitDeadline = { .tv_sec = deadline.tv_sec, .tv_nsec = deadline.tv_usec * 1000 };

			pthread_cond_timedwait(&client->readCond, &client->readMutex, &waitDeadline);

			/* What, if anything, has changed? */
			response = get_response_from_queue(client, id);
			still_time = time_remaining(&deadline, &remaining);
		}

		if (response || !still_time)
		{
			/* We either have a response or we have run out of time.
			 * Nothing more to do in either case.
			 */
			pthread_mutex_unlock(&client->readMutex);
			return response;
		}

		if (client->activeReader)
		{
			/* Something else is reading now.  Just wait again. */
			pthread_mutex_unlock(&client->readMutex);
		}
		else
		{
			/* Nothing else is reading now and we still have some time to go.
			 * Take control of the read here.
			 */
			int    oldstate;
			int    fd = client->fd;
			fd_set fds;
			char   buffer[4096];
			size_t len = 0;
			int    numReads;
			
			/* Take ownership of reading to lock out others and then release the mutex.
			 * The select/read could take a while and we must not block other threads
			 * from accessing their requests/responses.
			 */
			client->activeReader = 1;
			pthread_mutex_unlock(&client->readMutex);

			/* set up for select */
			FD_ZERO(&fds);
			FD_SET(fd, &fds);
			
			/* Wait till the end of the deadline or until we get a message */
                        thread_cleanup_push((thread_cleanup_t)close_client, (void*)client);
                        oldstate = thread_cancelability(TRUE);
			
			numReads = select(fd+1, &fds, NULL, NULL, &remaining);

			thread_cancelability(oldstate);
			thread_cleanup_pop(FALSE);
			if (numReads > 0)
			{
				len = read(fd, buffer, sizeof(buffer)-1);
			}

			/* Put any messages we received onto their respective queues.
			 * We need to hold the mutex when changing the queues.
			 */
			pthread_mutex_lock(&client->readMutex);
				
			if (len > 0)
			{
				buffer[len] = '\0';

				/* Queue any messages we received */
				process_buffer(fd, buffer, len);
			}

			/* We're going back to the top of the loop to check if we got a response.
			 * In the meantime we're not reading, so allow other threads access to
			 * their own incoming messages.
			 */
			client->activeReader = 0;

			pthread_cond_signal(&client->readCond);
			pthread_mutex_unlock(&client->readMutex);
		}
	}
}

/**
 * format and send a CRL fetch request, then wait for the response.
 */
static char *fetch_uri(smp_client *client, char *uri)
{
	xmlTextWriterPtr writer;
	smp_response *response = NULL;
	char id[16];
	char *msg = NULL;
	int c = 0;
	unsigned long thisid = client->request_id++;
	sprintf(id, "%d", thisid);
    
	writer = xmlNewTextWriter(xmlOutputBufferCreateFd(client->fd, NULL));
	if (writer == NULL)
	{
		DBG1(DBG_CFG, "opening SMP XML writer failed");
		return;
	}
	xmlTextWriterStartDocument(writer, NULL, NULL, NULL);
	xmlTextWriterStartElement(writer, "message");
	xmlTextWriterWriteAttribute(writer, "xmlns",
								"http://www.strongswan.org/smp/1.0");
	xmlTextWriterWriteAttribute(writer, "id", id);
	xmlTextWriterWriteAttribute(writer, "type", "request");
	xmlTextWriterStartElement(writer, "fetch"); /* <fetch> */
	xmlTextWriterStartElement(writer, "crl"); /* <crl> */
	xmlTextWriterWriteAttribute(writer, "uri", uri);    
	xmlTextWriterEndElement(writer); /* </crl> */
	xmlTextWriterEndElement(writer); /* </fetch> */
	/*  close document */
	xmlTextWriterEndDocument(writer);
	xmlFreeTextWriter(writer);
	response = wait_for_response(client, thisid, FETCH_RESPONSE_TIMEOUT);
	if (response)
	{
		msg = response->msg;
		free(response);
	}
	
	return msg;
}

/**
 * cleanup helper function for open file descriptors
 */

static void close_client(smp_client *client)
{
	pthread_mutex_lock(&client->readMutex);
	client->activeReader = 0;
	pthread_cond_signal(&client->readCond);
	pthread_mutex_unlock(&client->readMutex);
	close(client->fd);
}

/**
 * process a single SMP XML message
 */
static void process_single(int fd, char *buffer_in, size_t len)
{
	xmlTextReaderPtr reader;
	char *id = NULL, *type = NULL;
	char *buffer = NULL;
	
	DBG3(DBG_CFG, "got XML request: %b", buffer, len);

	/* Since requests are queued and the processing of the XML is
	 * deferred, we have to provide access to the buffer and the reader
	 * after this function returns.  That means we need to work with a
	 * copy of the buffer.  We dispose of it later, after the XML has
	 * all been decoded.
	 */
	buffer = malloc(len);
	if (buffer == NULL)
	{
		DBG1(DBG_CFG, "allocating memory failed");        
		return;
	}
	memcpy(buffer, buffer_in, len);
	
	reader = xmlReaderForMemory(buffer, len, NULL, NULL, 0);
	if (reader == NULL)
	{
		DBG1(DBG_CFG, "opening SMP XML reader failed");
		free(buffer);
		return;
	}

	/* read message type and id */
	while (xmlTextReaderRead(reader) == 1)
	{
		if (xmlTextReaderNodeType(reader) == XML_READER_TYPE_ELEMENT &&
			streq(xmlTextReaderConstName(reader), "message"))
		{
			id = xmlTextReaderGetAttribute(reader, "id");
			type = xmlTextReaderGetAttribute(reader, "type");
			break;
		}
	}

	/* process message */
	if (id && type)
	{
		if (streq(type, "request"))
		{
			if (queue_request(buffer, reader, id, fd))
			{
				/* Don't dispose of these here.  We need them to be
				 * available later when the request is taken off the
				 * queue for processing.
				 */
				buffer = NULL;
				reader = NULL;
			}
	    }
	    else if (streq(type, "response"))
	    {
	    	response(reader, id, fd);
	    }
		else
		{
			DBG1(DBG_CFG, "Unknown message type: %s", type);
		}
	}
	
	if (id)
	{
		free(id);
	}
	if (type)
	{
		free(type);
	}
	if (reader);
	{
		xmlFreeTextReader(reader);
	}
	if (buffer);
	{
		free(buffer);
	}
	
	return;
}


/**
 * process a buffer containing one or more SMP XML messages
 */
static void process_buffer(int fd, char *buffer, size_t len)
{
	/* buffer is NULL terminated but could potentially contain
	 * multiple SMP messages which must be separated before being
	 * passed to the xmlTextReader */
	char *s = buffer;
	int num_msgs = 0, i;
	char *msg[SMP_MAX_MSGS_PER_BUFFER];
	
	for (i = 0; i < SMP_MAX_MSGS_PER_BUFFER; ++i)
	{
		msg[i] = NULL;
	}

	while ((s = strstr(s, "<?xml ")) != NULL)
	{
		if (num_msgs >= SMP_MAX_MSGS_PER_BUFFER)
		{
			DBG1(DBG_CFG, "SMP: Too many msgs in buffer");
			break;
		}
		msg[num_msgs++] = s++;
	}

	/* now process each SMP message individually */
	for (i = 0; i < num_msgs; ++i)
	{
		/* if we have another message to follow, make sure this one
		   is NULL terminated before passing to reader. However we
		   don't know how long the current message is so just terminate
		   it at the start of the next message. */
		if (msg[i+1])
			msg[i+1][0] = '\0';
		if (msg[i][0] == '\0')
			msg[i][0] = '<';

		/* don't attempt to read anything which doesn't look like a
		   complete message */
		if (strstr(msg[i], "</message>"))
		{
			//DBG1(DBG_CFG, "Processing msg %d:\n'%s'", i, msg[i]);
			process_single(fd, msg[i], strlen(msg[i]));
		}
		else
		{
			DBG1(DBG_CFG, "Dropping incomplete message '%s'", msg[i]);
		}
	}
}

#endif
/**
 * read from a opened connection and process it
 */
static job_requeue_t process(int *fdp)
{
	int fd = *fdp;
        smp_client *client = add_client(fd);
	/* Loop until we get a request or the socket closes */
	for(;;)
	{
		smp_request *req = NULL;
		status_t status = NOT_FOUND;

		/* Make sure we hold the mutex while we can modify the request queue */
		pthread_mutex_lock(&client->readMutex);

		/* Check whether there's a request already on the request queue.
		 * If so remove the oldest one.
		 */
		status = client->requests->remove_first(client->requests, (void**)&req);

		while (client->activeReader && (status != SUCCESS))
		{
			/* Some other thread is reading and there was nothing already queued
			 * for us to read.  Just wait for a while for something to change.
			 * The other reader will wake us up when it gets something.
			 */
			pthread_cond_wait(&client->readCond, &client->readMutex);
			
			status = client->requests->remove_first(client->requests, (void**)&req);
		}
		if (status == SUCCESS)
		{
			/* We have a message to process.  That might take a while or block,
			 * so make sure we release the mutex before trying to process it.
			 */
			pthread_mutex_unlock(&client->readMutex);

			request(req->reader, req->id, fd);
			free(req->id);
			xmlFreeTextReader(req->reader);
			free(req->buffer);
			free(req);

			return JOB_REQUEUE_FAIR;
		}

		if (client->activeReader)
		{
			/* The other reader is still working, or another reader has started meantime.
			 * Just try the loop again.
			 */
			pthread_mutex_unlock(&client->readMutex);
		}
                else
                {
			/* There's no other reader and we hold the mutex */
			int oldstate, fd = *fdp;
			char buffer[4096];
			size_t len;
			/* Take ownership of reading and then release the mutex while we block in the read */
			client->activeReader = 1;
			pthread_mutex_unlock(&client->readMutex);
	                thread_cleanup_push((thread_cleanup_t)close_client, (void*)&fd);
	                oldstate = thread_cancelability(TRUE);
	                len = read(fd, buffer, sizeof(buffer));
			thread_cancelability(oldstate);
			thread_cleanup_pop(FALSE);
			if (len <= 0)
			{
				/* Client has closed the connection */
				pthread_mutex_lock(&client->readMutex);
				client->activeReader = 0;
				pthread_cond_signal(&client->readCond);
				pthread_mutex_unlock(&client->readMutex);
				
				/* TODO What happens to another reading thread if we remove
				 * the client from under it?
				 */
				remove_client(fd);
				close(fd);
				DBG2(DBG_CFG, "SMP XML connection closed");
				
				return JOB_REQUEUE_NONE;
			}
			buffer[len] = '\0';

			/* Split the buffer into individual messages and put them on their
			 * respective queues.  We need the mutex when changing the queues.
			 */
			pthread_mutex_lock(&client->readMutex);
			
			process_buffer(fd, buffer, len);

			/* Signal to any other threads that we are not reading right now.
			 * This is needed since we're about to loop and the first thing
			 * we'll do is check if there were any requests queued.  If so, that
			 * could block, so allow other threads to take care of reading their
			 * own messages while we do that.
			 */
			client->activeReader = 0;
			
			pthread_cond_signal(&client->readCond);
			pthread_mutex_unlock(&client->readMutex);
		}

                
        }
	return JOB_REQUEUE_FAIR;;
}

/**
 * accept from XML socket and create jobs to process connections
 */
static job_requeue_t dispatch(private_smp_t *this)
{
	struct sockaddr_un strokeaddr;
	int fd, *fdp, strokeaddrlen = sizeof(strokeaddr);
	callback_job_t *job;
	bool oldstate;

	/* wait for connections, but allow thread to terminate */
	oldstate = thread_cancelability(TRUE);
	fd = accept(this->socket, (struct sockaddr *)&strokeaddr, &strokeaddrlen);
	thread_cancelability(oldstate);

	if (fd < 0)
	{
		DBG1(DBG_CFG, "accepting SMP XML socket failed: %s", strerror(errno));
		sleep(1);
		return JOB_REQUEUE_FAIR;;
	}

	fdp = malloc_thing(int);
	*fdp = fd;
	job = callback_job_create((callback_job_cb_t)process, fdp, free,
							  (callback_job_cancel_t)return_false);
	lib->processor->queue_job(lib->processor, (job_t*)job);

	return JOB_REQUEUE_DIRECT;
}

METHOD(plugin_t, get_name, char*,
	private_smp_t *this)
{
	return "smp";
}

METHOD(plugin_t, get_features, int,
	private_smp_t *this, plugin_feature_t *features[])
{
	static plugin_feature_t f[] = {
		PLUGIN_NOOP,
			PLUGIN_PROVIDE(CUSTOM, "smp"),
	};
	*features = f;
	return countof(f);
}

METHOD(plugin_t, destroy, void,
	private_smp_t *this)
{
	close(this->socket);
	lib->fetcher->remove_fetcher(lib->fetcher,(fetcher_constructor_t)smp_fetcher_create);
        free(this->listener);
	free(this);
}
#if 1
/**
 * Listener implementation
 */
static bool child_state_change(listener_t *this, ike_sa_t *ike_sa,
							   child_sa_t *child_sa, child_sa_state_t state)
{
	return TRUE;
}

static bool ike_state_change(listener_t *this, ike_sa_t *ike_sa,
							 ike_sa_state_t state)
{
	smp_client *client = NULL;
	xmlTextWriterPtr writer;
	unsigned long thisid;
	host_t *remote;
	
	DBG2(DBG_CFG, "SMP got ike state change %N->%N with failure %d",
					ike_sa_state_names, ike_sa->get_state(ike_sa),
					ike_sa_state_names, state,
					ike_sa->get_failure(ike_sa));
	
	if (smp_clients->get_last(smp_clients, (void**)&client) == SUCCESS)
	{
		writer = xmlNewTextWriter(xmlOutputBufferCreateFd(client->fd, NULL));
		if (writer == NULL)
		{
			DBG1(DBG_CFG, "opening SMP XML writer failed");
			return;
		}
		thisid = client->request_id++;
		xmlTextWriterStartDocument(writer, NULL, NULL, NULL);
		xmlTextWriterStartElement(writer, "message");
		xmlTextWriterWriteAttribute(writer, "xmlns",
									"http://www.strongswan.org/smp/1.0");
		xmlTextWriterWriteFormatAttribute(writer, "id", "%d", thisid);
		xmlTextWriterWriteAttribute(writer, "type", "notification");
		xmlTextWriterStartElement(writer, "state"); /* <state> */
		xmlTextWriterWriteAttribute(writer, "type", "ikesa");
		
		xmlTextWriterWriteFormatElement(writer, "id", "%d",
						ike_sa->get_unique_id(ike_sa));
		xmlTextWriterWriteFormatElement(writer, "oldstate", "%N",
						ike_sa_state_lower_names, ike_sa->get_state(ike_sa));
		xmlTextWriterWriteFormatElement(writer, "newstate", "%N",
						ike_sa_state_lower_names, state);
		xmlTextWriterWriteFormatElement(writer, "failure", "%N",
						ike_failure_names, ike_sa->get_failure(ike_sa));
		xmlTextWriterWriteElement(writer, "peerconfig", ike_sa->get_name(ike_sa));
		/* <remote> */
		remote = ike_sa->get_other_host(ike_sa);
		xmlTextWriterStartElement(writer, "remote");
		write_id(writer, "identification", ike_sa->get_other_id(ike_sa));
		write_address(writer, "address", remote);
		xmlTextWriterEndElement(writer);
		/* </remote> */
		xmlTextWriterEndElement(writer); /* </state> */
		/*  close document */
		xmlTextWriterEndDocument(writer);
		xmlFreeTextWriter(writer);
	}

	return TRUE;
}

/**
 * See header
 */
listener_t *smp_listener_create()
{
	listener_t *this = malloc_thing(listener_t);
	
	memset(this, 0, sizeof(listener_t));
	this->child_state_change = (void*)child_state_change;
	this->ike_state_change = (void*)ike_state_change;
	
	return this;
}

#endif
/*
 * Described in header file
 */
plugin_t *smp_plugin_create()
{
	struct sockaddr_un unix_addr = { AF_UNIX, IPSEC_PIDDIR "/charon.xml"};
	private_smp_t *this;
	mode_t old;

	if (!lib->caps->check(lib->caps, CAP_CHOWN))
	{	/* required to chown(2) control socket */
		DBG1(DBG_CFG, "smp plugin requires CAP_CHOWN capability");
		return NULL;
	}

	INIT(this,
		.public = {
			.plugin = {
				.get_name = _get_name,
				.get_features = _get_features,
				.destroy = _destroy,
			},
		},
	);

	/* set up unix socket */
	this->socket = socket(AF_UNIX, SOCK_STREAM, 0);
	if (this->socket == -1)
	{
		DBG1(DBG_CFG, "could not create XML socket");
		free(this);
		return NULL;
	}

	unlink(unix_addr.sun_path);
	old = umask(S_IRWXO);
	if (bind(this->socket, (struct sockaddr *)&unix_addr, sizeof(unix_addr)) < 0)
	{
		DBG1(DBG_CFG, "could not bind XML socket: %s", strerror(errno));
		close(this->socket);
		free(this);
		return NULL;
	}
	umask(old);
	if (chown(unix_addr.sun_path, lib->caps->get_uid(lib->caps),
			  lib->caps->get_gid(lib->caps)) != 0)
	{
		DBG1(DBG_CFG, "changing XML socket permissions failed: %s", strerror(errno));
	}

	if (listen(this->socket, 5) < 0)
	{
		DBG1(DBG_CFG, "could not listen on XML socket: %s", strerror(errno));
		close(this->socket);
		free(this);
		return NULL;
	}

	lib->processor->queue_job(lib->processor,
		(job_t*)callback_job_create_with_prio((callback_job_cb_t)dispatch, this,
				NULL, (callback_job_cancel_t)return_false, JOB_PRIO_CRITICAL));

#if 1 

	smp_clients = linked_list_create();
	
	DBG1(DBG_CFG, "registering SMP fetchers for http and https");
	lib->fetcher->add_fetcher(lib->fetcher, 
					(fetcher_constructor_t)smp_fetcher_create, "http://");
	lib->fetcher->add_fetcher(lib->fetcher,
					(fetcher_constructor_t)smp_fetcher_create, "https://");


	this->listener = smp_listener_create();
	charon->bus->add_listener(charon->bus, this->listener);

#endif

	return &this->public.plugin;
}
