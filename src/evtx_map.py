#!/usr/bin/env python3

import logging
import re
import os
import argparse
import time

import sqlite3
import pandas as pd
import Evtx.Evtx as evtx
from geolite2 import geolite2

from os import listdir
from os.path import isfile, join

# STATIC VARIABLES
EVTX_MAP_DESCRIPTION = ""
COLUMN_NAMES = ["datetime", "target_cname", "user_sid", "src_ip", "src_country", "src_coordinates"]
parse_evtx_re = re.compile(r"SystemTime=\"(.*)\"></TimeCreated>.*<Computer>([aA-zZ0-9]+)"
                           r"</Computer>.*<Security UserID=\"(.*)\"></Security>.*<Param3>(.*)</Param3>",
                           re.MULTILINE|re.DOTALL)

# INITIATORS
log = logging.getLogger("evtx_map-logger")
reader = geolite2.reader()
df = pd.DataFrame(columns=COLUMN_NAMES)


def main():
    '''
    Main functionality of evtx_map
    '''
    # Retrieve and build script arguments
    parser = argparse.ArgumentParser(description=EVTX_MAP_DESCRIPTION)
    parser.add_argument("input", help="file or directory to run evtx_map against")
    parser.add_argument("-v", "--verbose", help="increase output verbosity",
                        action="store_true")
    parser.add_argument("-o", "--output", action="store", dest="out_file"
                        , help="store output to file")
    parser.add_argument("-e", "--export", help="export data to sqlite3 database file",
                        action="store_true")
    args = parser.parse_args()

    # Determine if we should print logging info to std.out
    if args.verbose:
        logging.basicConfig(level=os.environ.get("LOGLEVEL", "INFO"))

    log.info("Starting evtx_map...")
    log.info("Using the following arguments for evtx_map: {}".format(args))

    if not args.input:
        log.error("No input file provided {}".format(input))

    file_list = parse_input(args.input)
    log.info("found the following files => {}".format(file_list))

    #This will iterate over every file and extract data to be put inside a dataframe
    evtx_file: str
    for idx, evtx_file in enumerate(file_list):
        log.info("Processing {} via evtx_map".format(evtx_file))
        if os.path.isfile(evtx_file):
            try:
                parse_evtx_file(evtx_file)
            except:
                log.error("Unable to Process {} via evtx_map...Skipping".format(evtx_file))
    if len(df) > 0:
        results = print_evtx_stats(df)
        print(results)
        if args.out_file:
            try:
                save_out_to_file(results, args.out_file)
            except Exception as e:
                log.error("Unable to write results to file: {} [{}]".format(args.out_file, e))
        if args.export:
            try:
                db_info = save_df_to_sql(df)
                if db_info:
                    log.info("Saved data to {}".format(db_info))
            except Exception as e:
                log.error("Unable to create sqlite3 database file: {}".format(e))

    else:
        log.error("No remote connection events were found in these evtx logs")


def save_df_to_sql(df):
    '''
    Takes a dataframe and saves it to a sqlite3 database in the current working dir
    :param df:
    :return:
    '''
    db_name = str(time.time())+".db"
    log.info("Attempting to save sqlite3 db as {}".format(db_name))
    try:
        connection = sqlite3.connect(db_name)
        df.to_sql('remote_rdp_conn', connection, if_exists='append', index=False)
    except Exception as e:
        log.error("Unable to save db: {} [{}]".format(db_name, e))
        return False
    return(db_name)

def save_out_to_file(results, out_file):
    '''
    Will take the results and write them to a file
    :param results:
    :param out_file:
    :return:
    '''
    if isfile(out_file):
        log.error("{} is already a file!")
        out_file = '.'.join(out_file.split('.')[:-1]) + '_' + str(time.time()) + '.' + out_file.split('.')[-1]

    with open(out_file, 'a') as out:
        out.write(results)
    return

def print_evtx_stats(df):
    '''
    Takes a dataframe and create status output for it
    :param df:
    :return: print output for stdout about stats
    '''

    global_out = "\
Total Remote RDP Connections: {}\n\
Total Targeted Hosts: {} ({})\n\
Remote Connections observed from {} different countries and {} locations\n\
Countries Observed:\n\
\t{}\
".format(len(df), len(df.groupby('target_cname').count()),
             ', '.join(df.target_cname.unique()), len(df.groupby('src_country').size()),
             len(df.groupby('src_coordinates').size()), '\n\t'.join(df.src_country.unique()))

    for target in df.target_cname.unique():
        host_out = "[[Remote Connections to {}]]\n".format(target)
        for index, row in df.loc[df['target_cname'] == target].iterrows():
            host_out += "From {} ({}) by {} on {} [Coordinates: {}]\n".format(row['src_ip'], row['src_country'],
                                                                              row['user_sid'], row['datetime'],
                                                                              row['src_coordinates'])
    output = '\
==============================================================\n\
EVTMAP OUTPUT \n\
==============================================================\n\
--------------------------------------------------------------\n\
Global Statistics \n\
--------------------------------------------------------------\n\n\
{}\n\n\
--------------------------------------------------------------\n\
Host Specific Results \n\
--------------------------------------------------------------\n\n\
{}\n\
'.format(global_out, host_out)
    return output

def parse_evtx_file(evtx_file):
    '''
    Takes evtx_file parses data from each event entry and adds it to a dataframe
    :param evtx_file:
    :return:
    '''
    with evtx.Evtx(evtx_file) as evtxlog:
        for record in evtxlog.records():
            if "Param" in record.xml():
                r = re.search(parse_evtx_re, record.xml())
                if r:
                    date_time, target_cname, user_sid, src_ip = r.group(1), r.group(2), r.group(3), r.group(4)
                    src_country, src_lat, src_long = reader.get(src_ip)['country']['iso_code'], \
                                                     reader.get(src_ip)['location']['latitude'], \
                                                     reader.get(src_ip)['location']['longitude']
                    log.info("{}, {}, {}, {} ({}) | Lat/Long: {}, {}".format(date_time, target_cname, user_sid, src_ip,
                                                                          src_country, src_lat, src_long))
                    df.loc[len(df)] = [pd.to_datetime(date_time, errors='coerce'), target_cname,
                                       user_sid, src_ip, src_country,
                                                               "{},{}".format(src_lat, src_long)]

def parse_input(input):
    '''
        Takes the input from the CLI and returns a list of all the files evtx_map will run against
    '''
    file_list = []

    if os.path.isdir(input):
        log.info("{} is a directory, will run evtx_map against all files".format(input))
        file_list = ['{}{}'.format(input,f) for f in listdir(input) if isfile(join(input, f))]
    else:
        log.info("{} is NOT a directory, will run evtx_map against this input as a file".format(input))
        file_list.append(input)

    return(file_list)

if __name__ == "__main__":
    main()