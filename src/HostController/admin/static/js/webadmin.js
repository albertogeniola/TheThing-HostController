/**
 * Created by Alberto Geniola on 10/06/2017.
 */
var UPDAER_INTERVAL = 3000;
var webadminApp = angular.module('webadminApp', ['ui.bootstrap']);

// Define the `WebadminWorkers` controller on the `webadminApp` module
webadminApp.controller('WebadminWorkers', function WebadminWorkers($scope, $http, $timeout) {
    $scope.worker_query={};

    workersUpdater = function(){
        // Update the workers
        var query_data = {};
        for (var p in $scope.worker_query){
            if ($scope.worker_query[p] !== "")
                query_data[p] = $scope.worker_query[p];
        }

        $http({
          method: 'GET',
          url: '/workers',
          params:query_data
        }).then(function successCallback(response) {
            $scope.workers = response.data.result;
            $timeout(workersUpdater, UPDAER_INTERVAL);
          }, function errorCallback(response) {
            // TODO: notify the failure?
            $timeout(workersUpdater, UPDAER_INTERVAL);
          });
    };

    // Start the updater
    workersUpdater();
});


// Define the `WebadminJobs` controller on the `webadminApp` module
webadminApp.controller('WebadminJobs', function WebadminJobs($scope, $http, $timeout, $uibModal) {
    // This represents the object containing the filtering options for the job updater. The view binds some filers
    // to this object so
    $scope.job_query={};
    $scope.selected_jobs = [];

    $scope.toggle_selected_jobs = function (job_id) {
        var index = $scope.selected_jobs.indexOf(job_id) ;
        if (index === -1)
            $scope.selected_jobs.push(job_id);
        else
            $scope.selected_jobs.splice(index, 1);
    };

    $scope.update_jobs = function(){
        // Update the jobs
        $scope.job_updating = true;
        var query_data = {};
        for (var p in $scope.job_query){
            if ($scope.job_query[p] !== "")
                query_data[p] = $scope.job_query[p];
        }

        $http({
          method: 'GET',
          url: '/jobs',
          params:query_data
        }).then(function successCallback(response) {
            $scope.jobs = response.data.result;
            $scope.job_updating = false;
          }, function errorCallback(response) {
            $scope.job_updating = false;
            // TODO: notify the failure?
          });
    };

    $scope.show_job_modal = function() {
        // First retrieve the aggregators from the webservice
        $http({
          method: 'GET',
          url: '/aggregators'
        }).then(function successCallback(response) {
            // This array is used as buffer for aggregator objects ({name:.., id:..}). The array is filled when the button
            // +Job is pressed, before showing the new job modal.
            var aggregators = response.data.result;

            // We have aggregators, show the modal dialog.
            var modalInstance = $uibModal.open({
                animation: true,
                component: 'modalComponent',
                templateUrl: 'new_job_modal.html',
                controller:'NewJobController',
                resolve:{
                    aggregators:function(){
                        return aggregators;
                    }
                }
            });
          }, function errorCallback(response) {
            alert("Error: could not retrieve the aggregator list from the web service.")
          });
    };

    $scope.show_experiment_assignment_modal = function (){
        // First retrieve the list of testbeds to be shown in the modal
        $http({
          method: 'GET',
          url: '/test_beds'
        }).then(function successCallback(response) {
            var test_beds = response.data.result;

            // We have the test_beds, show the modal dialog.
            var modalInstance = $uibModal.open({
                animation: true,
                component: 'modalComponent',
                templateUrl: 'assign_job_to_experiment_modal.html',
                controller:'AssignJobToExperimentController',
                resolve:{
                    test_beds:function(){
                        return test_beds;
                    },
                    job_ids: function () {
                        return $scope.selected_jobs;
                    }
                }
            });
          }, function errorCallback(response) {
            alert("Error: could not retrieve the testbed list from the web service.")
          });
    };

    // Trigger the update
    $scope.update_jobs();
});

webadminApp.controller('AssignJobToExperimentController', function AssignJobToExperimentController($scope, $http, $uibModalInstance, $timeout, test_beds, job_ids) {
    // Feed the testbed to the UI
    $scope.test_beds = test_beds;
    $scope.job_ids = job_ids;
    $scope.job_ids_str = job_ids.join(',');

    // The following variable is used as indicator of progress. We assume to be idle when progress == 0.
    // Instead, when there is any action in pending status, progress > 0
    $scope.progress = 0;

    // Used to abort file upload
    $scope.cancel = function() {
        $uibModalInstance.dismiss('cancel');
    };

    // Create the experiments
    $scope.assign_experiment = function () {
        $scope.progress = $scope.job_ids.length;
        $scope.pb_max = $scope.job_ids.length;

        // If the user has selected more job ids, we need to execute multiple POSTs.
        angular.forEach($scope.job_ids, function (job_id, key) {

            // Put data into the form encoded envelope
            var payload = {};
            payload["test_bed_id"] = $scope.test_bed_id;
            payload["job_id"] = job_id;

            $http({
                url: '/experiments',
                method: 'POST',
                data: payload,
                headers: {'Content-Type': undefined},
                transformRequest: function (data, headersGetter) {
                    var formData = new FormData();
                    angular.forEach(data, function (value, key) {
                        formData.append(key, value);
                    });
                    var headers = headersGetter();
                    delete headers['Content-Type'];
                    return formData;
                }
            }).then(function (data) {
                $scope.progress--;

                if ($scope.progress===0)
                    // Dismiss the dialog
                    $uibModalInstance.dismiss('cancel');

            }, function (data) {
                $scope.progress--;
                alert("There was an error while adding the job: "+data.data.error_info);
            });
        });
    };
});

webadminApp.controller('NewJobController', function NewJobController($scope, $http, $uibModalInstance, aggregators) {
    // Flag used to preventthe user to submit multiple upload requests once one has been fired.
    // The view will disable some UIs when this flag is set.
    $scope.uploading = false;

    // Setup the aggregators received by the caller.
    $scope.aggregators = aggregators;

    // Setup a function for setting the file to be uploaded. Unfortunately we cannot use classic NG-MODEL with
    // file inputs.
    $scope.set_upload_job_file = function(files) {
        if (!files)
            $scope.selected_job_file = null;
        else
            $scope.selected_job_file = files[0];
    };

    // Used to abort file upload
    $scope.cancel = function() {
        $uibModalInstance.dismiss('cancel');
    };

    // This is the function that triggers the AJAX upload. It will be called via CLICK on the Upload button
    $scope.upload_job = function () {
        var file = $scope.selected_job_file;
        if (!file) {
            alert("Please select a file first.");
            return;
        }

        // Put data into the form encoded envelope
        var payload = {};
        for (var i in $scope.new_job_form_model) {
            payload[i] = $scope.new_job_form_model[i];
        }
        payload["file"] = file;

        $scope.uploading = true;
        $http({
            url: '/jobs',
            method: 'POST',
            data: payload,
            headers: {'Content-Type': undefined},
            transformRequest: function (data, headersGetter) {
                var formData = new FormData();
                angular.forEach(data, function (value, key) {
                    formData.append(key, value);
                });
                var headers = headersGetter();
                delete headers['Content-Type'];
                return formData;
            }
        }).then(function (data) {
            $scope.uploading = false;
            // Dismiss the dialog
            $uibModalInstance.dismiss('cancel');
        }, function (data) {
            $scope.uploading = false;
            alert("There was an error while adding the job: "+data.data.error_info);
        });
    };
});

// Define the `WebadminExperiments` controller on the `webadminApp` module
webadminApp.controller('WebadminExperiments', function WebadminExperiments($scope, $http, $timeout) {
    $scope.experiment_query={};
    $scope.update_experiments = function(){
        // Update the jobs
        var query_data = {};
        for (var p in $scope.experiment_query){
            if ($scope.experiment_query[p] !== "")
                query_data[p] = $scope.experiment_query[p];
        }

        $http({
          method: 'GET',
          url: '/experiments',
          params:query_data
        }).then(function successCallback(response) {
            $scope.experiments = response.data.result;
            $timeout(experimentsUpdater, UPDAER_INTERVAL);
          }, function errorCallback(response) {
            // TODO: notify the failure?
            $timeout(experimentsUpdater, UPDAER_INTERVAL);
          });
    };

    // Start trigger a first update
    $scope.update_experiments();
});
