__IGNORE__SETTINGS__ERROR = True

from logic.db import *
import getopt
import sys
import os
import json
from sqlalchemy.sql.expression import bindparam

if __name__=='__main__':

    argv = sys.argv[1:]

    # Check for result json file, or read id from stdin
    result_json_file = None

    try:
      opts, args = getopt.getopt(argv,"f:",["file="])
    except getopt.GetoptError:
      print "Invalid parameters."
      sys.exit(2)

    file = None
    data = None

    for opt, arg in opts:
        if opt == '-f':
            # Check if the file exists
            if not os.path.isfile(arg) or not os.path.exists(arg):
                print("Input file does not exists. Check the path.")
                exit(2)
            else:
                file = arg

    if file is None:
        print("Please Input the json data and exit by typing EOF (CTRL+D).")
        data = json.load(sys.stdin)
    else:
        # Open the file
        with open(file) as f:
            data = json.load(f)

    print("Loaded %d objects." % len(data))

    # Create session
    session = sessionmaker()

    # List of dictionary including primary key
    try:
        for o in data:
            id = o['id']
            pups = o.get('install_time_pups')
            ok = o.get('finished_ok')
            reason = o.get('failure_reason')
            dbo = session.query(Experiment).get(id)
            dbo.installation_ok = ok
            dbo.installation_failure_reason = reason
            dbo.installation_pups_shown = pups
            session.commit()

    except:
        session.rollback()
        raise
    finally:
        session.close()