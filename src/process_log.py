import re
import sys
import time
import datetime
import collections

from collections import Counter

# Challenge 1: List the top 10 most active host/IP addresses
# that have accessed the site.
def host_or_ip(LOGFILE, OUTPUTDIR, most_active_hosts=10):
    host_frequency = dict()

    # Open the log file in Read mode and process lines.
    with open(LOGFILE, 'r') as log_file:
        for line in log_file:
            host = get_host(line)

            if host in host_frequency:
                # For repeating hosts, increase the counter by 1.
                host_frequency[host] += 1
            else:
                # Add new hosts with 1 as a counter.
                host_frequency[host] = 1

    # Using Counter to find the top 10 most active host/IP addresses.
    most_active = Counter(host_frequency)

    # Write the results in the hosts.txt.
    with open(OUTPUTDIR, 'w') as hosts_file:
        for key, value in most_active.most_common(most_active_hosts):
            hosts_file.write('{},{}\n'.format(key, value))


# Challenge 2: Identify the 10 resources that consume the most
# bandwidth on the site.
def most_traffic(LOGFILE, OUTPUTDIR, most_resources=10):
    resource_bytes = dict()

    # Open the log file in Read mode and process lines.
    with open(LOGFILE, 'r') as log_file:
        for line in log_file:
            resource = get_resource(line)
            bytes = get_bytes(line)

            if resource in resource_bytes:
                # For repeating resources increase the byte size.
                resource_bytes[resource] += int(bytes)
            else:
                # For new resources use the current byte.
                resource_bytes[resource] = int(bytes)

    # Using Counter to find the 10 resources that consume the most bandwidth.
    most_active = Counter(resource_bytes)

    # Write the results in the resources.txt.
    with open(OUTPUTDIR, 'w') as resources_file:
        for key, value in most_active.most_common(most_resources):
            resources_file.write('{}\n'.format(key))


# Challenge 3: List in descending order the site's 10 busiest
# (i.e. most frequently visited) 60-minute period.
def most_busiest(LOGFILE, OUTPUTDIR, most_resources=10, time_interval=60):
    resource_busy = dict()
    resource_bucket = dict()
    resource_bucket_filter = dict()

    # Open the log file in Read mode and create dictionary with
    # timestamp as a key and # of accesses as value.
    with open(LOGFILE, 'r') as log_file:
        for line in log_file:
            access_time = get_time(line)

            if access_time not in resource_busy:
                resource_busy[access_time] = 1
            else:
                resource_busy[access_time] += 1
        last_timestamp_in_log = access_time

    # Find the earliest time stamp and create a 60-minute long window.
    bucket_start_time = min(resource_busy)
    bucket_end_time = add_minutes(bucket_start_time, time_interval)

    # Find the log file duration in seconds.
    log_duration = get_time_delta(bucket_start_time, last_timestamp_in_log)

    # Create a bucket for the earliest timestamp and count # of events in 1 hour.
    resource_bucket[bucket_start_time] = 0 # Initial value.

    # Create the first bucket and store timestamp:#_of_accesses in it.
    for sec in range(time_interval * 60):
        time_to_check = add_seconds(bucket_start_time, sec)

        if time_to_check in resource_busy:
            resource_bucket[bucket_start_time] += resource_busy[time_to_check]

    # Get ready for the big process.
    resource_bucket_filter[bucket_start_time] = resource_bucket[bucket_start_time]
    next_bucket_start_time = bucket_start_time

    # Process all timestamps starting from the earliest.
    for i in range(1, log_duration + 2): # +2 to process the latest entry too.
        next_bucket_start_time = add_seconds(bucket_start_time, 1)
        next_bucket_end_time = add_minutes(next_bucket_start_time, time_interval)

        # Count each buckets values by using this logic:
        # current_bucket = previous_backet
        #                - previous_backet_without_its_first_second
        #                + current_bucket's_last_second_only
        # Move the current window by 1 second in each loop.
        bucket_prev = resource_bucket[bucket_start_time] \
                      if bucket_start_time in resource_bucket else 0
        resource_prev_first_sec = resource_busy[bucket_start_time] \
                      if bucket_start_time in resource_busy else 0
        resource_next_first_sec = resource_busy[next_bucket_end_time] \
                      if next_bucket_end_time in resource_busy else 0
        resource_bucket[next_bucket_start_time] = bucket_prev \
                      - resource_prev_first_sec \
                      + resource_next_first_sec
        
        # Construct the final dictionary by filtering necessary items.
        if next_bucket_start_time in resource_busy:
            resource_bucket_filter[next_bucket_start_time] \
            = resource_bucket[next_bucket_start_time]

        bucket_start_time = next_bucket_start_time # Move the time window.
        bucket_end_time = next_bucket_end_time

    # Using Counter to find the 10 resources that consume the most bandwidth.
    most_active = Counter(resource_bucket_filter)
    
    # Write the results in the hours.txt.
    with open(OUTPUTDIR, 'w') as busy_file:
        for key, value in most_active.most_common(most_resources):
            busy_file.write('{},{}\n'.format(datetime_to_string(key), value))


# Challenge 4: Detect patterns of three consecutive failed login attempts over
# 20 seconds in order to block all further attempts to reach the site from the
# same IP address for the next 5 minutes.
def blocked_failed(LOGFILE, OUTPUTDIR, attempts=3, period=20, blockminutes=5):
    block = dict()
    time_line = collections.OrderedDict()
    ERRORCODE = '401'
    SUCCESSCODE = '200'
    MAXATTEMPTS = attempts
    SECONDWONDOW = period # seconds
    BLOCKDURATION = blockminutes * 60 # seconds

    # Open the log file in Read mode and block.txt in Write mode.
    with open(LOGFILE, 'r') as log_file, open(OUTPUTDIR, 'w') as blocked_hosts:
        for line in log_file:
            access_time = get_time(line)
            reply_code = get_reply_code(line)
            host = get_host(line)

            if host not in block: # We have not seen this new host.
                if reply_code == ERRORCODE: # Failed login attempt. Count it.
                    block[host] = 1
                else: # Successful login attempt. Reset the counter.
                    block[host] = 0
            else: # We have seen this host before.
                if reply_code == ERRORCODE: # Failed login attempt. Count it.
                    block[host] += 1
                    if block[host] > MAXATTEMPTS:
                        time_line[access_time] = line

                        # Get the first item's key, e.g. the first fails time.
                        start_time = time_line.iteritems().next()[0]

                        for atime in time_line:
                            # If within block duration,
                            # write failed attempts to file.
                            if get_time_delta(start_time, access_time) <= BLOCKDURATION:
                                # Pop the atime's value (if exists) and write to file.
                                # Else pop returns None without raising an error.
                                blocked_hosts.write(time_line.pop(atime, None))
                            else: # Block duration passed, reset the counter.
                                time_line[atime][:] = []
                else: # If login succeeded, reset the counter.
                    block[host] = 0


def get_time(line, LOGTIMEFORMAT='%d/%b/%Y:%H:%M:%S -0400'):
    # Returns date + time + time-zone of a line in the log.
    # Returns datetime.
    date_resource = line.split('[')[1]
    date_time = date_resource.split(']')[0]
    return datetime.datetime.strptime(date_time, LOGTIMEFORMAT)


def datetime_to_string(dt, TIMEFORMAT='%d/%b/%Y:%H:%M:%S -0400'):
    # Converts datetime to str.
    return datetime.datetime.strftime(dt, TIMEFORMAT)


def timestr_to_datetime(timestr, TIMEFORMAT='%d/%b/%Y:%H:%M:%S -0400'):
    # Converts str to datetime.
    return datetime.datetime.strptime(timestr, TIMEFORMAT)


def get_time_delta(start_time, end_time, TIMEFORMAT='%d/%b/%Y:%H:%M:%S -0400'):
    # Returns time difference in seconds.
    return (end_time - start_time).seconds


def add_minutes(given_time, minute=60):
    # Adds minutes to the given time.
    # Returns datetime.
    return given_time + datetime.timedelta(minutes = minute)


def add_seconds(given_time, second=60):
    # Adds seconds to the given time.
    # Returns datetime.
    return given_time + datetime.timedelta(seconds = second)


def get_host(line):
    # Returns the hostname/IP address.
    return line.split('[')[0][:-5]


def get_reply_code(line):
    # Returns the HTTP reply code.
    return line.split()[-2]


def get_resource(line):
    # Return the resource of a line in the log.
    request_resource_using_split = line.split('[')[1]
    resources = request_resource_using_split.split()

    if 'HTTP' not in resources[-3]:
        # Some lines in the log have HTTP, some do not. Handling the issue.
        resource = resources[-3][:-1] # [:-1] to delete the last " char.
    elif len(resources) <= 5:
        resource = resources[-3][1:-1] # [1:-1] to delete " and " chars.
    else:
        resource = resources[-4]
    return resource


def get_resource_regex(line):
    # Return the resource of a line in the log.
    # Similar to get_resource, but uses regex.
    request_resource = re.search('"(.*)"', line).group(1) # All characters between " and ".

    if ' ' in request_resource:
        resource = request_resource.split()[1]
    else:
        resource = request_resource
    return resource


def get_bytes(line):
    # Return the bytes of a line in the log.
    bytes = line.split()[-1]

    # Some lines in the log list have the "-" character in the bytes field.
    # Interpreted "-" as 0 bytes.
    if bytes == '-':
        bytes = 0
    return bytes


def main():
    # Reads input arguments and calls methods for all 4 challenges.
    # Also measures the running time of each method.
    LOGFILE         = sys.argv[1]
    OUTPUTHOSTS     = sys.argv[2]
    OUTPUTHOURS     = sys.argv[3]
    OUTPUTRESOURCES = sys.argv[4]
    OUTPUTBLOCKED   = sys.argv[5]

    start_time = time.time()
    print "\nChallenge 1: List the top 10 most active host/IP addresses..."
    host_or_ip(LOGFILE, OUTPUTHOSTS)
    print "Done. Took {} seconds.".format(time.time() - start_time)

    start_time = time.time()
    print "\nChallenge 2: Identify 10 resources that consume most bandwidth...."
    most_traffic(LOGFILE, OUTPUTRESOURCES)
    print "Done. Took {} seconds.".format(time.time() - start_time)

    start_time = time.time()
    print "\nChallenge 3: List 10 busiest 60-minute period..."
    most_busiest(LOGFILE, OUTPUTHOURS)
    print "Done. Took {} seconds.".format(time.time() - start_time)

    start_time = time.time()
    print "\nChallenge 4: Detect 3 consecutive failed login attempts..."
    blocked_failed(LOGFILE, OUTPUTBLOCKED)
    print "Done. Took {} seconds.".format(time.time() - start_time)

if __name__ == '__main__':
    main()
