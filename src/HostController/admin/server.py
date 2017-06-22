import os
import json
import logging as Logging
from logging import FileHandler
import re
from datetime import datetime
from flask import Flask, request, send_from_directory, redirect, Response
from werkzeug.utils import secure_filename
from HostController.logic.db import *


# Logging: web_admin
web_admin = Logging.getLogger("web_admin")
fname = os.path.join(CFG.logs_directory, "web_admin.log")
hdlr = FileHandler(fname, mode='w')
formatter = Logging.Formatter('%(asctime)s %(levelname)s %(processName)s %(message)s')
hdlr.setFormatter(formatter)
web_admin.setLevel(Logging.getLevelName(CFG.log_level))
web_admin.addHandler(hdlr)


app = Flask(__name__)
STATIC_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'static')
DATETIME_FORMAT_STRING = "%Y-%m-%d %H:%M:%S.%f"


class JsonResponse():
    _error = None
    _error_info = None
    _result = None
    _status = None

    def __init__(self, error=False, result=None, error_info=None, status=200):
        self._error = error
        self._result = result
        self._error_info = error_info
        self._status = status

    def __str__(self):
        return self.to_json()

    def to_json(self):
        return json.dumps({'error': self._error,
                'error_info': self._error_info,
                'result': self._result})

    def make_response(self):
        return Response(response=self.to_json(),
                        content_type="application/json",
                        mimetype="application/json",
                        status=self._status)


worker_query_structure = [
        ['id', 'int', Worker.id],
        ['hc_id', 'int', Worker.hc_id],
        ['mac', 'str', Worker.mac],
        ['startdate', 'datetime', Worker.startdate],
        ['status', 'enum', Worker.status],
        ['status_date', 'datetime', Worker.status_date],
        ['experiment_id', 'int', Worker.experiment_id],
    ]

experiment_query_structure = [
        ['id', 'int', Experiment.id],
        ['analysis_in_progress', 'bool', Experiment.analysis_in_progress],
        ['job_id', 'int', Experiment.job_id],
        ['test_bed_id', 'int', Experiment.test_bed_id],
        ['startdate', 'datetime', Experiment.startdate],
        ['finishdate', 'datetime', Experiment.finishdate],
        ['duration', 'int', Experiment.duration],
        ['result', 'str', Experiment.result],
        ['attempt', 'int', Experiment.attempt],
        ['retrying', 'bool', Experiment.retrying],
        ['network_summary_attempt', 'int', Experiment.network_summary_attempt],
        ['report_processed', 'bool', Experiment.report_processed],
        ['injector_exit_code', 'int', Experiment.injector_exit_code],
        ['ui_bot_exit_status', 'str', Experiment.ui_bot_exit_status],
        ['installation_ok', 'bool', Experiment.installation_ok],
        ['installation_failure_reason', 'str', Experiment.installation_failure_reason],
        ['product_name', 'str', Experiment.product_name],
        ['description', 'str', Experiment.description],
        ['file_version', 'str', Experiment.file_version],
        ['company_name', 'str', Experiment.company_name],
        ['original_file_name', 'str', Experiment.original_file_name],
        ['product_version', 'str', Experiment.product_version],
        ['network_conf', 'str', Experiment.network_conf]
    ]

job_query_structure = [
        ['id', 'int', Job.id],
        ['fname', 'str', Job.fname],
        ['downlink', 'str', Job.downlink],
        ['downdate', 'str', Job.downdate],
        ['path', 'str', Job.path],
        ['md5', 'str', Job.md5],
        ['sha1', 'str', Job.sha1],
        ['fuzzy', 'str', Job.fuzzy],
        ['aggregator_id', 'int', Job.aggregator_id]
    ]

test_bed_query_structure = [
    ['id', 'int', TestBed.id],
    ['name', 'str', TestBed.name]
]

aggregator_query_structure = [
        ['id', 'int', Aggregator.id],
        ['name', 'str', Aggregator.name],
        ['url', 'str', Aggregator.url]
    ]


def query_maker(query, parameter_name, parameter_type, column):
    if parameter_type == 'int':
        # When we have an integer parameter, we want to check for equality, less than and greater than.
        # We do recognize the following switches:
        # PARAMETERNAME -> equality
        # PARAMETERNAME_lt -> Less Than
        # PARAMETERNAME_gt -> Greater Than
        equality_check = request.args.get(parameter_name.lower())
        lt_check = request.args.get("%s_lt" % parameter_name.lower())
        gt_check = request.args.get("%s_gt" % parameter_name.lower())

        if equality_check is not None:
            equality_check = int(equality_check)
            query=query.filter(column == equality_check)

        if lt_check is not None:
            lt_check = int(lt_check)
            query=query.filter(column < lt_check)

        if gt_check is not None:
            gt_check = int(gt_check)
            query=query.filter(column > gt_check)

    elif parameter_type == 'str':
        # Check the string using the LIKE statement regardless of the input string
        param = request.args.get(parameter_name.lower())
        if param is not None:
            param = str(param)
            query=query.filter(column.like(param))

    elif parameter_type == 'bool':
        param = request.args.get(parameter_name.lower())
        if param is not None:
            param = param.lower()
            if param == 'true':
                pram = True
            elif param == 'false':
                param = False
            else:
                raise ValueError("Invalid boolean value specified")
            query=query.filter(column == param)

    elif parameter_type == 'datetime':
        param = request.args.get(parameter_name.lower())

        lt_check = request.args.get("%s_lt" % parameter_name.lower())
        gt_check = request.args.get("%s_gt" % parameter_name.lower())

        if lt_check is not None:
            param = datetime.datetime.strptime(str(param), DATETIME_FORMAT_STRING)
            query=query.filter(column < param)

        if gt_check is not None:
            param = datetime.datetime.strptime(str(param), DATETIME_FORMAT_STRING)
            query=query.filter(column > param)

    elif parameter_type == 'enum':
        param = request.args.get(parameter_name.lower())
        if param is not None:
            param = str(param)
            query=query.filter(column == param)

    else:
        raise ValueError("Invalid parameter type specified.")

    return query


def from_db_to_dist(structure, db_obj):
    tmp = {}
    for i in structure:
        parameter_name = i[0]
        parameter_type = i[1]
        column = i[2]
        # Dangerous method here, but it speeds up the entire thing.
        value = eval("db_obj.%s" % str(column.key))
        if value is not None:
            if parameter_type == 'int':
                value = int(value)
            elif parameter_type == 'str':
                value = str(value)
            elif parameter_type == 'datetime':
                value = value.strftime(DATETIME_FORMAT_STRING)
            elif parameter_type == 'bool':
                value = bool(value)
            else:
                value = str(value)

        tmp[parameter_name] = value

    return tmp


@app.route("/")
def index():
    return redirect("/static/workers.html")


@app.route("/workers")
def get_workers():
    result = []
    session = sessionmaker()

    try:
        q = session.query(Worker)

        # Compose the db query for each possible parameter in experiment query
        for i in worker_query_structure:
            parameter_name, parameter_type, column = i
            q = query_maker(query=q,
                            parameter_name=parameter_name,
                            parameter_type=parameter_type,
                            column=column)
        workers = q.all()

        for w in workers:
            # Let's wrap the most important worker informations
            tmp = from_db_to_dist(worker_query_structure,w)
            result.append(tmp)

        return JsonResponse(error=False, result=result).make_response()

    except Exception as e:
        web_admin.exception(e)
        raise e
    finally:
        session.close()


@app.route("/experiments", methods=('GET',))
def get_experiments():
    result = []
    session = sessionmaker()

    try:
        q = session.query(Experiment)

        # Compose the db query for each possible parameter in experiment query
        for i in experiment_query_structure:
            parameter_name, parameter_type, column = i
            q = query_maker(query=q,
                            parameter_name=parameter_name,
                            parameter_type=parameter_type,
                            column=column)
        exps = q.all()

        for e in exps:
            # Let's wrap the most important worker informations
            tmp = from_db_to_dist(experiment_query_structure, e)
            result.append(tmp)

        return JsonResponse(error=False, result=result).make_response()

    except Exception as e:
        web_admin.exception(e)
        raise e
    finally:
        session.close()


@app.route("/experiments", methods=('POST',))
def add_experiments():
    result = []
    session = sessionmaker()

    # This web method expects a test_bed and a job for creating an experiment
    test_bed_id = request.form.get('test_bed_id')
    try:
        test_bed_id = int(test_bed_id)

        # Check if the test_bed exists in our database
        tb = session.query(TestBed).get(test_bed_id)  # This generates an error if the testbed is invalid

    except Exception:
        return JsonResponse(error=True, result=None, error_info="Invalid test_bed_id has been specified. "
                                                                "This parameter should be a valid integer pointing to "
                                                                "a specific test_bed in the database",
                            status=400).make_response()

    job_id = request.form.get('job_id')
    try:
        job_id = int(job_id)

        # Check if the test_bed exists in our database
        tb = session.query(Job).get(job_id)  # This generates an error if the testbed is invalid

    except Exception:
        return JsonResponse(error=True, result=None, error_info="Invalid job_id has been specified. "
                                                                "This parameter should be a valid integer pointing to "
                                                                "a specific Job in the database",
                            status=400).make_response()

    # One last step: is this combination of job-testbed already issued?
    el = session.query(Experiment).filter(Experiment.test_bed_id==test_bed_id, Experiment.job_id==job_id).first()
    if el is not None:
        return JsonResponse(error=True, result=None, error_info="There already is an experiment assigned to this job "
                                                                "and to this test_bed. There cannot exist two "
                                                                "experiments referring to the same combination of job"
                                                                " and test_bed.",
                            status=409).make_response()

    # Great, we have everything we need
    jobmanager.create_experiment(job_id=job_id, test_bed_id=test_bed_id)
    return JsonResponse(error=False, result=None, status=201).make_response()


@app.route("/jobs", methods=('GET',))
def get_jobs():
    result = []
    session = sessionmaker()

    try:
        q = session.query(Job)

        # Compose the db query for each possible parameter in experiment query
        for i in job_query_structure:
            parameter_name, parameter_type, column = i
            q = query_maker(query=q,
                            parameter_name=parameter_name,
                            parameter_type=parameter_type,
                            column=column)
        jobs = q.all()

        for j in jobs:
            # Let's wrap the most important worker informations
            tmp = from_db_to_dist(job_query_structure, j)
            result.append(tmp)

        return JsonResponse(error=False, result=result).make_response()

    except Exception as e:
        web_admin.exception(e)
        raise e
    finally:
        session.close()


@app.route("/jobs", methods=('POST',))
def add_job():
    session = sessionmaker()
    try:
        # Check if we have everything we need to create a new Job into the DB
        aggregator_id = request.form.get('aggregator_id')
        try:
            aggregator_id = int(aggregator_id)
            agg_obj = session.query(Aggregator).filter(Aggregator.id == aggregator_id).first()
            if agg_obj is None:
                raise ValueError()
        except Exception:
            return JsonResponse(error=True, result=None, error_info="Invalid aggregator ID has been specified.", status=400).make_response()

        # If downdate is none, assume the item has been just downloaded
        # Otherwise check if it is valid and reject any invalid value.
        downdate = request.form.get('downdate')
        if downdate is None:
            downdate = datetime.datetime.now().strftime(DATETIME_FORMAT_STRING)
        else:
            try:
                downdate = datetime.datetime.strptime(downdate, DATETIME_FORMAT_STRING).isoformat()
            except Exception:
                return JsonResponse(error=True,
                                    result=None,
                                    error_info="Invalid or wrong datetime format specified for downdate parameter."
                                               " Please use the following format: %s" % DATETIME_FORMAT_STRING,
                                    status=400).make_response()

        # Check if downlink has been specified.
        downlink = request.form.get('downlink')
        if downlink is None:
            return JsonResponse(error=True,
                                result=None,
                                error_info="Missing downlink parameter specified.",
                                status=400).make_response()
        else:
            # TODO: check if downlink is a valid URL?
            pass

        if 'file' not in request.files:
            return JsonResponse(error=True,
                                result=None,
                                error_info="Missing file parameter specified.",
                                status=400).make_response()
        file = request.files['file']
        # if user does not select file, browser also
        # submit a empty part without filename
        if file.filename == '':
            return JsonResponse(error=True,
                                result=None,
                                error_info="Missing file parameter specified.",
                                status=400).make_response()
        filename = secure_filename(file.filename)
        fpath = os.path.join(CFG.installers_base_dir, filename)

        dirname = os.path.dirname(fpath)
        basename = os.path.basename(fpath)
        RENAME_PATTERN = "^([0-9]+)(_)(.+)$"
        seq = 1

        # In case we have a file collision, make rename the file
        collision = os.path.isfile(fpath)

        while collision:
            m = re.match(RENAME_PATTERN, basename)
            if m:
                seq = int(m.group(1))
                basename = str(m.group(3))
                seq += 1
            basename = "%d_%s" % (seq, basename)
            fpath = os.path.join(dirname, basename)
            collision = os.path.isfile(fpath)

        try:
            file.save(fpath)
        except Exception:
            return JsonResponse(error=True,
                                result=None,
                                error_info="An error has occurred when saving the file into the server.",
                                status=500).make_response()

        try:
            jobmanager.create_job(path=fpath, aggregator_id=aggregator_id, downlink=downlink, downdate=downdate)
        except Exception:
            web_admin.exception("Error when saving job into the database")
            # If the file was saved, remove it now.
            if os.path.isfile(fpath):
                os.unlink(fpath)
            return JsonResponse(error=True,
                                result=None,
                                error_info="An error has occurred when adding the Job into the database.",
                                status=500).make_response()

        return JsonResponse(error=False, result=None, status=201).make_response()

    except Exception as e:
        web_admin.exception(e)
        raise e
    finally:
        session.close()


@app.route("/test_beds")
def get_test_beds():
    result = []
    session = sessionmaker()

    try:
        q = session.query(TestBed)

        # Compose the db query for each possible parameter in experiment query
        for i in test_bed_query_structure:
            parameter_name, parameter_type, column = i
            q = query_maker(query=q,
                            parameter_name=parameter_name,
                            parameter_type=parameter_type,
                            column=column)
        jobs = q.all()

        for j in jobs:
            # Let's wrap the most important worker informations
            tmp = from_db_to_dist(test_bed_query_structure, j)
            result.append(tmp)

        return JsonResponse(error=False, result=result).make_response()

    except Exception as e:
        web_admin.exception(e)
        raise e
    finally:
        session.close()


@app.route("/aggregators")
def get_aggregators():
    result = []
    session = sessionmaker()

    try:
        q = session.query(Aggregator)

        # Compose the db query for each possible parameter in experiment query
        for i in aggregator_query_structure:
            parameter_name, parameter_type, column = i
            q = query_maker(query=q,
                            parameter_name=parameter_name,
                            parameter_type=parameter_type,
                            column=column)
        jobs = q.all()

        for j in jobs:
            # Let's wrap the most important worker informations
            tmp = from_db_to_dist(aggregator_query_structure, j)
            result.append(tmp)

        return JsonResponse(error=False, result=result).make_response()

    except Exception as e:
        web_admin.exception(e)
        raise e
    finally:
        session.close()


@app.route("/<path:filename>")
def static_server(filename):
    path = os.path.join(STATIC_PATH, filename)
    return send_from_directory(STATIC_PATH, filename, as_attachment=False)

def main():
    app.run(host='127.0.0.1', port=80)


if __name__ == "__main__":
    main()
