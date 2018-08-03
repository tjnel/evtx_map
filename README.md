# EVTX MAP

## Purpose
The goal of this script is to map out remote RDP connections and other events from Windows event logs.

## TODO List
* Add more event log type support
* Create visualizations 

## Installing

To run evtx_map you would need to install the prerequisites below.

### Prerequisites
You will need install the following packages
```
sudo pip install python-evtx
sudo pip install pandas
sudo pip install maxminddb-geolite2
``` 

## Usage

#### Options 
```
usage: evtx_map.py [-h] [-v] [-o OUT_FILE] [-e] input

positional arguments:
  input                 file or directory to run evtx_map against

optional arguments:
  -h, --help            show this help message and exit
  -v, --verbose         increase output verbosity
  -o OUT_FILE, --output OUT_FILE
                        store output to file
  -e, --export          export data to sqlite3 database file
```

#### Simple usage against single file
```
python evtx_map.py file.evtx
```

#### Run against directory with verbose output
```
python evtx_map.py /directory -v
```

#### Run against a file in verbose mode
```
evtx_map.py file.evtx -v
```

## Usage Video

[https://youtu.be/E35MPPEiEyc](https://youtu.be/E35MPPEiEyc)

## Built With

* [Python3](https://github.com/python/cpython)
* [Python-evtx](https://github.com/williballenthin/python-evtx)
* [Maxminddb-Geolite2](https://github.com/rr2do2/maxminddb-geolite2)

## Authors

* **TJ Nel** - *Initial work* - [TJNel](https://github.com/tjnel)

See also the list of [contributors](https://github.com/tjnel/hashlee/contributors) who participated in this project.

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details

## Acknowledgments

* Hat tip to [Andreas Schuster](https://www.dfrws.org/sites/default/files/session-files/pres-introducing_the_microsoft_vista_log_file_format.pdf) for doing the initial event log parsing work!
* Hat tip to [williballenthin](https://github.com/williballenthin/) for making a python package to parse EVTX