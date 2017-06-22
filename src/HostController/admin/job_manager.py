import sys
import argparse
import datetime
from HostController.logic import db
"""
This file implements a very simple command line interface for adding/deleting a job from the pool. It is just
a human interface for the database.
"""

# Default actions
_ACTION_LIST = "list"
_ACTION_ADD = "create"
_ACTION_DELETE = "delete"

# Jobs:
OBJECT_JOBS = "jobs"
JOBS_ACTIONS = (_ACTION_LIST, _ACTION_ADD, _ACTION_DELETE)

# Workers
OBJECT_WORKERS = "workers"
WORKERS_ACTIONS = (_ACTION_LIST,)

# Experiments
OBJECT_EXPERIMENTS = "experiments"
EXPERIMENTS_ACTIONS = (_ACTION_LIST,)

OBJECTS = (OBJECT_JOBS, OBJECT_WORKERS)


def main():

    # Configure the parser
    main_parser = argparse.ArgumentParser(description='Db manager utility. Used to control the central db.')

    # Add sub parsers
    object_parsers = main_parser.add_subparsers(help='additional help', title="subcommands",
                                            description="valid subcommands")

    # ********************* JOBS *********************
    # create the parser for the JOBS
    job_parser = object_parsers.add_parser(OBJECT_JOBS, help='Manage jobs')
    job_action_parsers = job_parser.add_subparsers(help='additional help', title="subcommands",
                   description="valid subcommands")

    # -- CREATE_JOB
    create_job_parser = job_action_parsers.add_parser(_ACTION_ADD, help='Create a new job')
    # path, aggregator, downlink, downdate, md5 = None, sha1 = None, fuzzy = None
    create_job_parser.add_argument('path', action='store', help='Path to the binary')
    create_job_parser.add_argument('--downlink', action='store', help='URL where the binary has been downloaded from.')
    create_job_parser.add_argument('--aggregator-id', action='store', type=int, help='Aggregator ID',
                                   default=db.jobmanager.get_or_create_aggregator("manual", "N/A"))
    create_job_parser.add_argument('--downdate', action='store', help='Date of download. If omitted, now() will be used.', default=datetime.datetime.now())
    create_job_parser.set_defaults(func=db.jobmanager.create_job)

    # -- LIST_JOBS
    list_job_parser = job_action_parsers.add_parser(_ACTION_LIST, help='List jobs')
    # Filtering options
    list_job_parser.add_argument('--id_is', action='store', default=None, type=int, help='Filter by equal ID.', metavar="ID",)
    list_job_parser.add_argument('--fname_like', action='store', default=None, type=str, metavar="FILE_NAME",
                                 help='Filter by LIKE operator on file name. You can use %% as wildcard operator.')
    list_job_parser.add_argument('--downlink_like', action='store', default=None, type=str, metavar="DOWNLOAD_LINK",
                                 help='Filter by LIKE operator on download link. You can use %% as wildcard operator.')
    list_job_parser.add_argument('--downdate_greater_than', action='store', default=None, type=lambda d: datetime.datetime.strptime(d, '%Y-%m-%d'), metavar="YYYY-MM-DD",
                                 help='Select all jobs created after specified date. Date must be specified in YYYY-MM-DD format.')
    list_job_parser.add_argument('--downdate_less_than', action='store', default=None, type=lambda d: datetime.datetime.strptime(d, '%Y-%m-%d'), metavar="YYYY-MM-DD",
                                 help='Select all jobs created before specified date. Date must be specified in YYYY-MM-DD format.')
    list_job_parser.add_argument('--assigned', dest="assigned_is", action='store_const', const=True, default=None,
                                 help='Select all jobs that have been already assigned to workers.')
    list_job_parser.add_argument('--not-assigned', dest="assigned_is", action='store_const', const=False, default=None,
                                 help='Select all jobs that have NOT been already assigned to workers.')
    list_job_parser.add_argument('--assigned-to', dest="assigned_to", action='store', default=None,
                                 help='Select all jobs to the specified worker id')
    list_job_parser.add_argument('--path_like', action='store', default=None, type=str, metavar="PATH",
                                 help='Filter jobs by LIKE operaton on PATH field. Wildcard character %% is supported.')
    list_job_parser.add_argument('--md5_is', action='store', default=None, type=str, metavar="MD5_HASH",
                                 help='Select all jobs strictly matching a specific MD5 value.')
    list_job_parser.add_argument('--sha1_is', action='store', default=None, type=str, metavar="SHA1_HASH",
                                 help='Select all jobs strictly matching a specific SHA1 value.')
    list_job_parser.add_argument('--fuzzy_like', action='store', default=None, type=str, metavar="FUZZY_HASH",
                                 help='Filter jobs by LIKE operation on Fuzzy field. Wildcard character %% is supported.')
    list_job_parser.add_argument('--aggregator_name_like', action='store', default=None, type=str, metavar="AGGREGATOR_NAME",
                                 help='Filter jobs by LIKE operation Aggregator Name field.')

    list_job_parser.set_defaults(func=db.jobmanager.print_list_filter_jobs)


    # ********************* EXPERIMENTS *********************
    exp_parser = object_parsers.add_parser(OBJECT_EXPERIMENTS, help='Manage experiments')
    exp_action_parsers = exp_parser.add_subparsers(help='additional help', title="subcommands",
                   description="valid subcommands")

    # -- CREATE_EXPERIMENT
    create_experiment_parser = exp_action_parsers.add_parser(_ACTION_ADD, help='Create a new experiment')

    create_experiment_parser.add_argument('job_id', action='store', type=int, help='ID of the Job to be processed')
    create_experiment_parser.add_argument('--test_bed_id', action='store', default=None, type=int, help='ID of the test_bed to use')
    create_experiment_parser.set_defaults(func=db.jobmanager.create_experiment)

    # -- List experiments... todo...

    # ********************* WORKERS *********************

    args = main_parser.parse_args()
    args.func(**vars(args))
    exit(0)

if __name__ == "__main__":
    main()
