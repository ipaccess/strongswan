/* C code produced by gperf version 3.0.3 */
/* Command-line: gperf -C -G -t src/starter/keywords.txt  */
/* Computed positions: -k'1-2,6,$' */

#if !((' ' == 32) && ('!' == 33) && ('"' == 34) && ('#' == 35) \
      && ('%' == 37) && ('&' == 38) && ('\'' == 39) && ('(' == 40) \
      && (')' == 41) && ('*' == 42) && ('+' == 43) && (',' == 44) \
      && ('-' == 45) && ('.' == 46) && ('/' == 47) && ('0' == 48) \
      && ('1' == 49) && ('2' == 50) && ('3' == 51) && ('4' == 52) \
      && ('5' == 53) && ('6' == 54) && ('7' == 55) && ('8' == 56) \
      && ('9' == 57) && (':' == 58) && (';' == 59) && ('<' == 60) \
      && ('=' == 61) && ('>' == 62) && ('?' == 63) && ('A' == 65) \
      && ('B' == 66) && ('C' == 67) && ('D' == 68) && ('E' == 69) \
      && ('F' == 70) && ('G' == 71) && ('H' == 72) && ('I' == 73) \
      && ('J' == 74) && ('K' == 75) && ('L' == 76) && ('M' == 77) \
      && ('N' == 78) && ('O' == 79) && ('P' == 80) && ('Q' == 81) \
      && ('R' == 82) && ('S' == 83) && ('T' == 84) && ('U' == 85) \
      && ('V' == 86) && ('W' == 87) && ('X' == 88) && ('Y' == 89) \
      && ('Z' == 90) && ('[' == 91) && ('\\' == 92) && (']' == 93) \
      && ('^' == 94) && ('_' == 95) && ('a' == 97) && ('b' == 98) \
      && ('c' == 99) && ('d' == 100) && ('e' == 101) && ('f' == 102) \
      && ('g' == 103) && ('h' == 104) && ('i' == 105) && ('j' == 106) \
      && ('k' == 107) && ('l' == 108) && ('m' == 109) && ('n' == 110) \
      && ('o' == 111) && ('p' == 112) && ('q' == 113) && ('r' == 114) \
      && ('s' == 115) && ('t' == 116) && ('u' == 117) && ('v' == 118) \
      && ('w' == 119) && ('x' == 120) && ('y' == 121) && ('z' == 122) \
      && ('{' == 123) && ('|' == 124) && ('}' == 125) && ('~' == 126))
/* The character set is not based on ISO-646.  */
error "gperf generated tables don't work with this execution character set. Please report a bug to <bug-gnu-gperf@gnu.org>."
#endif

#line 1 "src/starter/keywords.txt"

/*
 * Copyright (C) 2005 Andreas Steffen
 * Hochschule fuer Technik Rapperswil, Switzerland
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

#include <string.h>

#include "keywords.h"

#line 22 "src/starter/keywords.txt"
struct kw_entry {
    char *name;
    kw_token_t token;
};

#define TOTAL_KEYWORDS 141
#define MIN_WORD_LENGTH 2
#define MAX_WORD_LENGTH 17
#define MIN_HASH_VALUE 8
#define MAX_HASH_VALUE 403
/* maximum key range = 396, duplicates = 0 */

#ifdef __GNUC__
__inline
#else
#ifdef __cplusplus
inline
#endif
#endif
static unsigned int
hash (str, len)
     register const char *str;
     register unsigned int len;
{
  static const unsigned short asso_values[] =
    {
      404, 404, 404, 404, 404, 404, 404, 404, 404, 404,
      404, 404, 404, 404, 404, 404, 404, 404, 404, 404,
      404, 404, 404, 404, 404, 404, 404, 404, 404, 404,
      404, 404, 404, 404, 404, 404, 404, 404, 404, 404,
      404, 404, 404, 404, 404, 404, 404, 404, 404,  25,
        5, 404, 404, 404, 404, 404, 404, 404, 404, 404,
      404, 404, 404, 404, 404, 404, 404, 404, 404, 404,
      404, 404, 404, 404, 404, 404, 404, 404, 404, 404,
      404, 404, 404, 404, 404, 404, 404, 404, 404, 404,
      404, 404, 404, 404, 404,   0, 404,  55, 404,  50,
      115,   0, 100,  90, 160,   0, 404, 170,   0,  70,
       60, 115,  90, 404,  10,  20,   5, 120,  15,   0,
        0,  20,   5, 404, 404, 404, 404, 404, 404, 404,
      404, 404, 404, 404, 404, 404, 404, 404, 404, 404,
      404, 404, 404, 404, 404, 404, 404, 404, 404, 404,
      404, 404, 404, 404, 404, 404, 404, 404, 404, 404,
      404, 404, 404, 404, 404, 404, 404, 404, 404, 404,
      404, 404, 404, 404, 404, 404, 404, 404, 404, 404,
      404, 404, 404, 404, 404, 404, 404, 404, 404, 404,
      404, 404, 404, 404, 404, 404, 404, 404, 404, 404,
      404, 404, 404, 404, 404, 404, 404, 404, 404, 404,
      404, 404, 404, 404, 404, 404, 404, 404, 404, 404,
      404, 404, 404, 404, 404, 404, 404, 404, 404, 404,
      404, 404, 404, 404, 404, 404, 404, 404, 404, 404,
      404, 404, 404, 404, 404, 404, 404, 404, 404, 404,
      404, 404, 404, 404, 404, 404
    };
  register int hval = len;

  switch (hval)
    {
      default:
        hval += asso_values[(unsigned char)str[5]];
      /*FALLTHROUGH*/
      case 5:
      case 4:
      case 3:
      case 2:
        hval += asso_values[(unsigned char)str[1]];
      /*FALLTHROUGH*/
      case 1:
        hval += asso_values[(unsigned char)str[0]];
        break;
    }
  return hval + asso_values[(unsigned char)str[len - 1]];
}

static const struct kw_entry wordlist[] =
  {
    {""}, {""}, {""}, {""}, {""}, {""}, {""}, {""},
#line 45 "src/starter/keywords.txt"
    {"lifetime",          KW_KEYLIFE},
#line 87 "src/starter/keywords.txt"
    {"left",              KW_LEFT},
    {""}, {""},
#line 94 "src/starter/keywords.txt"
    {"leftfirewall",      KW_LEFTFIREWALL},
#line 104 "src/starter/keywords.txt"
    {"leftcert",          KW_LEFTCERT},
#line 105 "src/starter/keywords.txt"
    {"leftcert2",         KW_LEFTCERT2},
    {""}, {""},
#line 107 "src/starter/keywords.txt"
    {"leftsendcert",      KW_LEFTSENDCERT},
    {""}, {""},
#line 112 "src/starter/keywords.txt"
    {"right",             KW_RIGHT},
    {""}, {""},
#line 126 "src/starter/keywords.txt"
    {"rightid2",          KW_RIGHTID2},
    {""}, {""},
#line 111 "src/starter/keywords.txt"
    {"leftgroups2",       KW_LEFTGROUPS2},
#line 113 "src/starter/keywords.txt"
    {"rightikeport",      KW_RIGHTIKEPORT},
#line 91 "src/starter/keywords.txt"
    {"leftprotoport",     KW_LEFTPROTOPORT},
#line 33 "src/starter/keywords.txt"
    {"type",              KW_TYPE},
#line 102 "src/starter/keywords.txt"
    {"leftsigkey",        KW_LEFTSIGKEY},
    {""},
#line 96 "src/starter/keywords.txt"
    {"leftallowany",      KW_LEFTALLOWANY},
    {""},
#line 106 "src/starter/keywords.txt"
    {"leftcertpolicy",    KW_LEFTCERTPOLICY},
#line 55 "src/starter/keywords.txt"
    {"rekey",             KW_REKEY},
    {""}, {""}, {""}, {""},
#line 110 "src/starter/keywords.txt"
    {"leftgroups",        KW_LEFTGROUPS},
    {""}, {""},
#line 74 "src/starter/keywords.txt"
    {"replay_window",     KW_REPLAY_WINDOW},
    {""}, {""},
#line 114 "src/starter/keywords.txt"
    {"rightsubnet",       KW_RIGHTSUBNET},
    {""},
#line 132 "src/starter/keywords.txt"
    {"rightsendcert",     KW_RIGHTSENDCERT},
#line 49 "src/starter/keywords.txt"
    {"lifebytes",         KW_LIFEBYTES},
    {""}, {""}, {""},
#line 103 "src/starter/keywords.txt"
    {"leftrsasigkey",     KW_LEFTSIGKEY},
#line 128 "src/starter/keywords.txt"
    {"rightrsasigkey",    KW_RIGHTSIGKEY},
    {""}, {""}, {""}, {""}, {""}, {""},
#line 127 "src/starter/keywords.txt"
    {"rightsigkey",       KW_RIGHTSIGKEY},
    {""}, {""}, {""},
#line 31 "src/starter/keywords.txt"
    {"strictcrlpolicy",   KW_STRICTCRLPOLICY},
#line 80 "src/starter/keywords.txt"
    {"crluri",            KW_CRLURI},
#line 109 "src/starter/keywords.txt"
    {"leftca2",           KW_LEFTCA2},
    {""}, {""}, {""},
#line 86 "src/starter/keywords.txt"
    {"certuribase",       KW_CERTURIBASE},
#line 82 "src/starter/keywords.txt"
    {"crluri2",           KW_CRLURI2},
#line 134 "src/starter/keywords.txt"
    {"rightca2",          KW_RIGHTCA2},
#line 129 "src/starter/keywords.txt"
    {"rightcert",         KW_RIGHTCERT},
#line 130 "src/starter/keywords.txt"
    {"rightcert2",        KW_RIGHTCERT2},
#line 153 "src/starter/keywords.txt"
    {"crlcheckinterval",  KW_SETUP_DEPRECATED},
    {""}, {""}, {""},
#line 124 "src/starter/keywords.txt"
    {"rightauth2",        KW_RIGHTAUTH2},
    {""}, {""}, {""}, {""},
#line 158 "src/starter/keywords.txt"
    {"virtual_private",   KW_SETUP_DEPRECATED},
#line 51 "src/starter/keywords.txt"
    {"lifepackets",       KW_LIFEPACKETS},
#line 93 "src/starter/keywords.txt"
    {"leftdns",           KW_LEFTDNS},
    {""},
#line 69 "src/starter/keywords.txt"
    {"xauth_identity",    KW_XAUTH_IDENTITY},
#line 66 "src/starter/keywords.txt"
    {"inactivity",        KW_INACTIVITY},
#line 64 "src/starter/keywords.txt"
    {"retransmit_count",  KW_RETRANSMIT_COUNT},
#line 81 "src/starter/keywords.txt"
    {"crluri1",           KW_CRLURI},
#line 35 "src/starter/keywords.txt"
    {"installpolicy",     KW_INSTALLPOLICY},
    {""},
#line 131 "src/starter/keywords.txt"
    {"rightcertpolicy",   KW_RIGHTCERTPOLICY},
#line 63 "src/starter/keywords.txt"
    {"retransmit_timer",  KW_RETRANSMIT_TIMER},
    {""},
#line 121 "src/starter/keywords.txt"
    {"rightallowany",     KW_RIGHTALLOWANY},
    {""}, {""},
#line 168 "src/starter/keywords.txt"
    {"leftnexthop",       KW_LEFT_DEPRECATED},
    {""}, {""}, {""}, {""},
#line 71 "src/starter/keywords.txt"
    {"mediated_by",       KW_MEDIATED_BY},
#line 115 "src/starter/keywords.txt"
    {"rightsubnetwithin", KW_RIGHTSUBNET},
    {""}, {""}, {""}, {""}, {""},
#line 58 "src/starter/keywords.txt"
    {"esp",               KW_ESP},
    {""}, {""},
#line 108 "src/starter/keywords.txt"
    {"leftca",            KW_LEFTCA},
#line 136 "src/starter/keywords.txt"
    {"rightgroups2",      KW_RIGHTGROUPS2},
    {""},
#line 116 "src/starter/keywords.txt"
    {"rightprotoport",    KW_RIGHTPROTOPORT},
    {""},
#line 79 "src/starter/keywords.txt"
    {"cacert",            KW_CACERT},
#line 133 "src/starter/keywords.txt"
    {"rightca",           KW_RIGHTCA},
#line 119 "src/starter/keywords.txt"
    {"rightfirewall",     KW_RIGHTFIREWALL},
#line 54 "src/starter/keywords.txt"
    {"rekeyfuzz",         KW_REKEYFUZZ},
#line 143 "src/starter/keywords.txt"
    {"plutostart",        KW_SETUP_DEPRECATED},
    {""},
#line 101 "src/starter/keywords.txt"
    {"leftid2",           KW_LEFTID2},
    {""}, {""},
#line 73 "src/starter/keywords.txt"
    {"reqid",             KW_REQID},
#line 135 "src/starter/keywords.txt"
    {"rightgroups",       KW_RIGHTGROUPS},
#line 125 "src/starter/keywords.txt"
    {"rightid",           KW_RIGHTID},
#line 117 "src/starter/keywords.txt"
    {"rightsourceip",     KW_RIGHTSOURCEIP},
#line 99 "src/starter/keywords.txt"
    {"leftauth2",         KW_LEFTAUTH2},
#line 89 "src/starter/keywords.txt"
    {"leftsubnet",        KW_LEFTSUBNET},
    {""}, {""},
#line 155 "src/starter/keywords.txt"
    {"nat_traversal",     KW_SETUP_DEPRECATED},
    {""}, {""}, {""}, {""}, {""},
#line 70 "src/starter/keywords.txt"
    {"mediation",         KW_MEDIATION},
    {""}, {""}, {""},
#line 167 "src/starter/keywords.txt"
    {"eap",               KW_CONN_DEPRECATED},
#line 95 "src/starter/keywords.txt"
    {"lefthostaccess",    KW_LEFTHOSTACCESS},
    {""},
#line 47 "src/starter/keywords.txt"
    {"rekeymargin",       KW_REKEYMARGIN},
    {""},
#line 118 "src/starter/keywords.txt"
    {"rightdns",          KW_RIGHTDNS},
    {""}, {""}, {""}, {""},
#line 78 "src/starter/keywords.txt"
    {"tfc",               KW_TFC},
    {""},
#line 97 "src/starter/keywords.txt"
    {"leftupdown",        KW_LEFTUPDOWN},
    {""}, {""}, {""}, {""}, {""}, {""}, {""},
#line 150 "src/starter/keywords.txt"
    {"packetdefault",     KW_SETUP_DEPRECATED},
    {""}, {""}, {""},
#line 169 "src/starter/keywords.txt"
    {"rightnexthop",      KW_RIGHT_DEPRECATED},
#line 57 "src/starter/keywords.txt"
    {"ike",               KW_IKE},
#line 137 "src/starter/keywords.txt"
    {"also",              KW_ALSO},
#line 36 "src/starter/keywords.txt"
    {"aggressive",        KW_AGGRESSIVE},
#line 65 "src/starter/keywords.txt"
    {"closeaction",       KW_CLOSEACTION},
    {""},
#line 164 "src/starter/keywords.txt"
    {"ldapbase",          KW_CA_DEPRECATED},
    {""}, {""}, {""},
#line 83 "src/starter/keywords.txt"
    {"ocspuri",           KW_OCSPURI},
#line 42 "src/starter/keywords.txt"
    {"fragmentation",     KW_FRAGMENTATION},
#line 30 "src/starter/keywords.txt"
    {"cachecrls",         KW_CACHECRLS},
    {""},
#line 88 "src/starter/keywords.txt"
    {"leftikeport",       KW_LEFTIKEPORT},
    {""},
#line 85 "src/starter/keywords.txt"
    {"ocspuri2",          KW_OCSPURI2},
    {""},
#line 140 "src/starter/keywords.txt"
    {"interfaces",        KW_SETUP_DEPRECATED},
#line 40 "src/starter/keywords.txt"
    {"mobike",	           KW_MOBIKE},
#line 76 "src/starter/keywords.txt"
    {"mark_in",           KW_MARK_IN},
#line 34 "src/starter/keywords.txt"
    {"compress",          KW_COMPRESS},
#line 72 "src/starter/keywords.txt"
    {"me_peerid",         KW_ME_PEERID},
#line 48 "src/starter/keywords.txt"
    {"margintime",        KW_REKEYMARGIN},
#line 90 "src/starter/keywords.txt"
    {"leftsubnetwithin",  KW_LEFTSUBNET},
    {""}, {""}, {""}, {""},
#line 122 "src/starter/keywords.txt"
    {"rightupdown",       KW_RIGHTUPDOWN},
#line 38 "src/starter/keywords.txt"
    {"eap_identity",      KW_EAP_IDENTITY},
    {""}, {""},
#line 120 "src/starter/keywords.txt"
    {"righthostaccess",   KW_RIGHTHOSTACCESS},
    {""}, {""},
#line 84 "src/starter/keywords.txt"
    {"ocspuri1",          KW_OCSPURI},
#line 29 "src/starter/keywords.txt"
    {"uniqueids",         KW_UNIQUEIDS},
    {""}, {""}, {""},
#line 165 "src/starter/keywords.txt"
    {"pfs",               KW_PFS_DEPRECATED},
#line 148 "src/starter/keywords.txt"
    {"plutostderrlog",    KW_SETUP_DEPRECATED},
    {""},
#line 50 "src/starter/keywords.txt"
    {"marginbytes",       KW_MARGINBYTES},
#line 92 "src/starter/keywords.txt"
    {"leftsourceip",      KW_LEFTSOURCEIP},
#line 52 "src/starter/keywords.txt"
    {"marginpackets",     KW_MARGINPACKETS},
    {""},
#line 68 "src/starter/keywords.txt"
    {"xauth",             KW_XAUTH},
#line 37 "src/starter/keywords.txt"
    {"authby",            KW_AUTHBY},
    {""}, {""}, {""}, {""}, {""}, {""}, {""}, {""},
#line 157 "src/starter/keywords.txt"
    {"force_keepalive",   KW_SETUP_DEPRECATED},
#line 32 "src/starter/keywords.txt"
    {"keyexchange",       KW_KEYEXCHANGE},
    {""},
#line 60 "src/starter/keywords.txt"
    {"dpddelay",          KW_DPDDELAY},
#line 123 "src/starter/keywords.txt"
    {"rightauth",         KW_RIGHTAUTH},
#line 156 "src/starter/keywords.txt"
    {"keep_alive",        KW_SETUP_DEPRECATED},
#line 100 "src/starter/keywords.txt"
    {"leftid",            KW_LEFTID},
    {""}, {""}, {""}, {""}, {""}, {""},
#line 163 "src/starter/keywords.txt"
    {"ldaphost",          KW_CA_DEPRECATED},
    {""}, {""},
#line 41 "src/starter/keywords.txt"
    {"forceencaps",       KW_FORCEENCAPS},
    {""}, {""}, {""}, {""}, {""},
#line 141 "src/starter/keywords.txt"
    {"dumpdir",           KW_SETUP_DEPRECATED},
#line 77 "src/starter/keywords.txt"
    {"mark_out",          KW_MARK_OUT},
    {""}, {""}, {""},
#line 39 "src/starter/keywords.txt"
    {"aaa_identity",      KW_AAA_IDENTITY},
#line 149 "src/starter/keywords.txt"
    {"fragicmp",          KW_SETUP_DEPRECATED},
    {""}, {""},
#line 152 "src/starter/keywords.txt"
    {"overridemtu",       KW_SETUP_DEPRECATED},
    {""}, {""}, {""}, {""}, {""}, {""}, {""}, {""}, {""},
    {""}, {""}, {""}, {""}, {""}, {""},
#line 46 "src/starter/keywords.txt"
    {"keylife",           KW_KEYLIFE},
    {""},
#line 62 "src/starter/keywords.txt"
    {"dpdaction",         KW_DPDACTION},
    {""},
#line 44 "src/starter/keywords.txt"
    {"ikelifetime",       KW_IKELIFETIME},
    {""}, {""}, {""}, {""},
#line 142 "src/starter/keywords.txt"
    {"charonstart",       KW_SETUP_DEPRECATED},
    {""},
#line 98 "src/starter/keywords.txt"
    {"leftauth",          KW_LEFTAUTH},
    {""},
#line 61 "src/starter/keywords.txt"
    {"dpdtimeout",        KW_DPDTIMEOUT},
#line 53 "src/starter/keywords.txt"
    {"keyingtries",       KW_KEYINGTRIES},
    {""}, {""},
#line 138 "src/starter/keywords.txt"
    {"auto",              KW_AUTO},
    {""}, {""},
#line 159 "src/starter/keywords.txt"
    {"pkcs11module",      KW_PKCS11_DEPRECATED},
#line 154 "src/starter/keywords.txt"
    {"nocrsend",          KW_SETUP_DEPRECATED},
#line 75 "src/starter/keywords.txt"
    {"mark",              KW_MARK},
#line 161 "src/starter/keywords.txt"
    {"pkcs11keepstate",   KW_PKCS11_DEPRECATED},
    {""},
#line 151 "src/starter/keywords.txt"
    {"hidetos",           KW_SETUP_DEPRECATED},
    {""}, {""},
#line 145 "src/starter/keywords.txt"
    {"plutodebug",        KW_SETUP_DEPRECATED},
    {""}, {""}, {""}, {""}, {""}, {""}, {""}, {""}, {""},
    {""},
#line 162 "src/starter/keywords.txt"
    {"pkcs11proxy",       KW_PKCS11_DEPRECATED},
#line 43 "src/starter/keywords.txt"
    {"ikedscp",           KW_IKEDSCP,},
    {""},
#line 160 "src/starter/keywords.txt"
    {"pkcs11initargs",    KW_PKCS11_DEPRECATED},
    {""}, {""}, {""}, {""}, {""}, {""}, {""}, {""}, {""},
#line 147 "src/starter/keywords.txt"
    {"postpluto",         KW_SETUP_DEPRECATED},
    {""}, {""}, {""}, {""}, {""}, {""},
#line 56 "src/starter/keywords.txt"
    {"reauth",            KW_REAUTH},
    {""}, {""}, {""}, {""}, {""}, {""},
#line 146 "src/starter/keywords.txt"
    {"prepluto",          KW_SETUP_DEPRECATED},
    {""}, {""}, {""}, {""}, {""}, {""}, {""}, {""}, {""},
    {""}, {""}, {""}, {""}, {""}, {""}, {""}, {""}, {""},
    {""}, {""}, {""}, {""}, {""}, {""}, {""}, {""}, {""},
#line 28 "src/starter/keywords.txt"
    {"charondebug",       KW_CHARONDEBUG},
    {""}, {""}, {""}, {""}, {""},
#line 59 "src/starter/keywords.txt"
    {"ah",                KW_AH},
    {""}, {""}, {""}, {""}, {""}, {""}, {""},
#line 144 "src/starter/keywords.txt"
    {"klipsdebug",        KW_SETUP_DEPRECATED},
    {""}, {""}, {""}, {""}, {""}, {""}, {""}, {""}, {""},
    {""}, {""}, {""}, {""}, {""},
#line 67 "src/starter/keywords.txt"
    {"modeconfig",        KW_MODECONFIG},
    {""}, {""},
#line 166 "src/starter/keywords.txt"
    {"pfsgroup",          KW_PFS_DEPRECATED}
  };

#ifdef __GNUC__
__inline
#ifdef __GNUC_STDC_INLINE__
__attribute__ ((__gnu_inline__))
#endif
#endif
const struct kw_entry *
in_word_set (str, len)
     register const char *str;
     register unsigned int len;
{
  if (len <= MAX_WORD_LENGTH && len >= MIN_WORD_LENGTH)
    {
      register int key = hash (str, len);

      if (key <= MAX_HASH_VALUE && key >= 0)
        {
          register const char *s = wordlist[key].name;

          if (*str == *s && !strcmp (str + 1, s + 1))
            return &wordlist[key];
        }
    }
  return 0;
}
