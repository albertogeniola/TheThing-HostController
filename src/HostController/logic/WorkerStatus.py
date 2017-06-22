import enum


class WorkerStatus(enum.Enum):
    IDLE = 'IDLE'        # The Guest is powered off and can be started when needed
    BOOTING = 'BOOTING'     # The Guest is booting up.
    WAITING_JOB = 'WAITING_JOB' # The Guest is waiting a job from the HostController. This means it successfully contacted the HC
    ANALYZING = 'ANALYZING'   # The Guest is currently analyzing a job
    REPORTING = 'REPORTING'   # The Guest has collected the report and is reporting it back to HC
    SHUTTING_DOWN = 'SHUTTING_DOWN' # The guest is shutting down
    ERROR = 'ERROR'
    REVERTING = 'REVERTING'

WORKER_STATUS_VALUES = [WorkerStatus.IDLE,
                        WorkerStatus.BOOTING,
                        WorkerStatus.ANALYZING,
                        WorkerStatus.REPORTING,
                        WorkerStatus.SHUTTING_DOWN,
                        WorkerStatus.ERROR,
                        WorkerStatus.REVERTING]
