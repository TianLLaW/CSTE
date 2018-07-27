/*******************************************************************************************
 * Project:  jobqueen                                                                      *
 *                                                                                         *
 * Author :  hpluo									                                       *  
 *  																					   * 
 * Changelist: 																		       *
 * 20161011 add by hpluo  Version 0.0 													   *
 ******************************************************************************************/

#include "jobqueen.h"

struct JOB_QUEEN jobList[JOB_QUEEN_SIZE];
struct JOB_QUEEN* pJobPool;
struct JOB_QUEEN* pJobQueue;

void JobQueueInit(){
	int count;
	memset(&JobSocketsList, 0, sizeof(JobSocketsList));
	memset(jobList, 0, sizeof(jobList));
	pJobPool = jobList;
	for(count=0; count < JOB_QUEEN_SIZE; count++) {
		if(count >= JOB_QUEEN_SIZE) {
			jobList[count].pNextJob = NULL;
			break;
		}
		else{
			jobList[count].pNextJob = &(jobList[(count + 1)]);
		}
	}
	pJobQueue = NULL;
	JobSocketsList.debug = J_FALSE;
	return;
}

char* JobNameGet(JobQueen job)
{
	switch (job)
	{
		case JOB_HEART_BEAT:
			return "JOB_HEART_BEAT";
		case JOB_HEART_RESPONSE:
			return "JOB_HEART_RESPONSE";
		default:
			return "Unknow Job";
	}
}

void JobQueueInsertJobToQueue(struct JOB_QUEEN* newJob){
	struct JOB_QUEEN* pCurrentJob;
	struct JOB_QUEEN* temp;
	
	if(pJobQueue ==  NULL) {
		pJobQueue = newJob;
		newJob->pNextJob = NULL;
		return;
	}

	if(pJobQueue->nextEventTime >= newJob->nextEventTime) {
		temp = pJobQueue;
		pJobQueue = newJob;
		newJob->pNextJob = temp;
		return;
	}

		for(pCurrentJob = pJobQueue; pCurrentJob->pNextJob != NULL; pCurrentJob = pCurrentJob->pNextJob) {
			if((pCurrentJob->nextEventTime < newJob->nextEventTime) && (pCurrentJob->pNextJob->nextEventTime >= newJob->nextEventTime)) {
				temp = pCurrentJob->pNextJob;
				pCurrentJob->pNextJob = newJob;
				newJob->pNextJob = temp;
			return;
			}
		}
		/*Reached End*/
		pCurrentJob->pNextJob = newJob;
		newJob->pNextJob = NULL;
	return;
}

void JobQueueRemoveJobFromQueue(struct JOB_QUEEN* expiredJob){
	 memset(expiredJob, 0, sizeof(struct JOB_QUEEN));
	 expiredJob->pNextJob = pJobPool;
	 pJobPool = expiredJob;
	 return;
}


void JobQueueAddJob(unsigned int secondOffset, JobQueen job, JOB_BOOL (*processFunc)(void*), void (*printFunc)(void*), void* argumentPointer) {
	struct JOB_QUEEN* temp;
	struct JOB_QUEEN* newJobPoolHead;
	struct sysinfo info;
	
	sysinfo(&info);
	if(pJobPool == NULL) {
		printf("JobQueueAddJob Error JobPool full\n");
		return;
	}

    temp = pJobPool;
	newJobPoolHead = pJobPool->pNextJob;
	
	/*Fill in values for job*/
	temp->pNextJob = NULL;
	temp->job = job;

	temp->nextEventTime = info.uptime + secondOffset;
	temp->processFunc = processFunc;
	temp->printFunc = printFunc;
	temp->argumentPointer = argumentPointer;

	/*Update JobPool*/
	pJobPool = newJobPoolHead;


	JobQueueInsertJobToQueue(temp);
	
	return;
}

void JobQueueDeleteFirstJobByType(JobQueen job) {
  struct JOB_QUEEN *currentjob; 
  struct JOB_QUEEN *prevjob;

  prevjob = NULL;
  
  for(currentjob = pJobQueue; currentjob != NULL; currentjob = currentjob->pNextJob) {
      if((currentjob->job == job) && (currentjob->isRunning == J_FALSE)) {
          if (prevjob != NULL) {
              prevjob->pNextJob = currentjob->pNextJob;
          } else {
              pJobQueue = currentjob->pNextJob;
          }
          JobQueueRemoveJobFromQueue(currentjob);
		  return;
	  } else {
          prevjob = currentjob;
	  }
  }

  if(JobSocketsList.debug == J_TRUE) {
	printf("Cannot find %s in Job Queue\n", JobNameGet(job));
  }
  
  return;
}

void JobQueueDeleteAllJob() {
  struct JOB_QUEEN *tmp;

  while(pJobQueue != NULL) {
	  tmp = pJobQueue;
	  pJobQueue = pJobQueue->pNextJob;
	  JobQueueRemoveJobFromQueue(tmp);
  }

  pJobQueue = NULL;
  return;
}

void JobQueuePrintJob() {
    struct JOB_QUEEN *tmp;
	int counter;
	struct sysinfo info;
	
	sysinfo(&info);
	counter = 1;
    for(tmp=pJobQueue; tmp != NULL; tmp = tmp->pNextJob) {
		counter++;
    	printf("Job %d Job %s, Next Event Time In: %d seconds\n", counter++, JobNameGet(tmp->job), (tmp->nextEventTime - info.uptime));
		if(tmp->printFunc != NULL) {
			tmp->printFunc(tmp->argumentPointer);
		}
    }
	return;
}

JOB_BOOL JobQueueRegisterSocket(int socket, void (*processFunc)(void*), void* argument){
	int count;
	for(count=0; count< JOB_SOCKET_LIST_SIZE; count++) {
		if(JobSocketsList.socketArray[count].used == J_FALSE) {
			JobSocketsList.socketArray[count].used = J_TRUE;
			JobSocketsList.socketArray[count].socket = socket;
			JobSocketsList.socketArray[count].processSocketFunc = processFunc;
			JobSocketsList.socketArray[count].argument = argument;
			JobQueueMaxSocketValueUpdate();
			return J_TRUE;
		}
	}
	return J_FALSE;
}

JOB_BOOL JobQueueRemoveSocket(int socket){
	int count;
	for(count=0; count< JOB_SOCKET_LIST_SIZE; count++) {
		if(JobSocketsList.socketArray[count].socket == socket) {
			JobSocketsList.socketArray[count].used = J_FALSE;
			JobSocketsList.socketArray[count].socket = JOB_SOCKET_NO_ACTIVITY;
			JobSocketsList.socketArray[count].processSocketFunc = NULL;
			JobSocketsList.socketArray[count].argument = NULL;
			JobQueueMaxSocketValueUpdate();
			return J_TRUE;
		}
	}
	return J_FALSE;
}

void JobQueueMaxSocketValueUpdate(void){
	int count;
	for(count=0; count< JOB_SOCKET_LIST_SIZE; count++) {
		if(JobSocketsList.socketArray[count].socket > JobSocketsList.maxSocketValue) {
			JobSocketsList.maxSocketValue = JobSocketsList.socketArray[count].socket;
		}
	}
	return;
}

void JobQueueNextJobEventTimeGet(long* nextEventTime){

	struct sysinfo info;
	sysinfo(&info);
	if(pJobQueue != NULL) {
        if(pJobQueue->nextEventTime > info.uptime) {
			*nextEventTime = (pJobQueue->nextEventTime - info.uptime);
		}
		else{
            *nextEventTime = JOB_MIN_WAIT_TIME;
        }
	}
	else{
		*nextEventTime = JOB_DEFAULT_IDLE_TIME;
	}
	return;
}

void JobQueueExecutionLoop(){
	JobQueueNextJobEventTimeGet(&JobSocketsList.nextEventTime);
	if(JobSocketsList.debug == J_TRUE) {
	  JobQueuePrintJob();
	} 
	WaitForNextJob(JobSocketsList.nextEventTime);
	JobQueueExcuteJob();
	return;
}

void WaitForNextJob(long timeout){
	fd_set readfds;
	struct timeval t;
	int count;
	int activity;

	FD_ZERO(&readfds);
	for(count=0; count< JOB_SOCKET_LIST_SIZE; count++) {
		if(JobSocketsList.socketArray[count].used == J_TRUE) {
			FD_SET(JobSocketsList.socketArray[count].socket, &readfds);
		}
	}
	t.tv_sec = timeout;
	t.tv_usec = 0;
	if(JobSocketsList.debug == J_TRUE) {
		printf("WaitForNextJob wait %d seconds for next job\n", timeout);
	}
	activity = select((JobSocketsList.maxSocketValue + 1), &readfds, NULL, NULL, &t);

	if(activity > JOB_SOCKET_NO_ACTIVITY) {
		for(count=0; count< JOB_SOCKET_LIST_SIZE; count++) {
			 if((JobSocketsList.socketArray[count].used == J_TRUE) && (FD_ISSET(JobSocketsList.socketArray[count].socket, &readfds))){
				 if(JobSocketsList.socketArray[count].processSocketFunc != NULL) {
				 	JobSocketsList.socketArray[count].processSocketFunc(JobSocketsList.socketArray[count].argument);
				 }
			 }
		}
	}
	return;
}

void JobQueueDebug(JOB_BOOL enable){
	JobSocketsList.debug = enable;
}

void JobQueueExcuteJob(){
	/*Execute all jobs before current time*/
  struct JOB_QUEEN *currentJob;
  JOB_BOOL result;
  struct sysinfo info;
  sysinfo(&info);

  while(pJobQueue != NULL) {
      if(pJobQueue->nextEventTime <= info.uptime) {
          /*Detach job from job queue*/
          currentJob = pJobQueue;
		  pJobQueue = pJobQueue->pNextJob;

          /*Run Job Func*/
          if(currentJob->processFunc != NULL) {
              currentJob->isRunning = J_TRUE;
              result = currentJob->processFunc(currentJob->argumentPointer);
          }

          /*Put job back to pool*/
          JobQueueRemoveJobFromQueue(currentJob);
      } else {
          break;
	  }
  }
  return;
}

