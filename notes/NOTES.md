# 20/07/2020

## BPF maps

There seems to be two main types of BPF maps:
ARRAY and HASHMAP

There is different ones with different properties and we will need to identify the correct subtype. Bogdan has started looking into them.

## Maintaining provenance "states"

CamFlow, as other LSM such as SELinux, associate a datastructure with kernel objects to maintain states.
This is not possible via BPF.
Those states are needed to build correct graph.

I suggest to maintain BPF HASHMAP storing those states.

objects such as task, process, inode have alloc and free functions that would allow to add/remove objects from the HASHMAP.

I would suggest focusing on those three types to start with and identifying a minimum set of hooks to implement to demonstrate practicality.

### 31/07/2020

I have added an example of this yesterday. Seems a reasonable approach as long as we can identify unique identifiers for the lifetime of the object.

## Recording provenance

I suggest to separate this state management to the actual recording following similar separation to the standard CamFlow code.

I would suggest trying to implement some sort of ring-buffer (or identifying something equivalent such as perf events) where we record provenance graph elements as done in the normal CamFlow.

### Need to identify BPF ringbuffer

There is the perf one (thoug not sure if it can be used without providing a context pointer. Is that a problem?)

There is this Linux patch:
https://lwn.net/Articles/821456/

It seems in theory possible, but will need some though.

# Target/deadline

Bogdan needs to be done with a lot of this by October as class starts again.

I suggest we aim for EuroSys 2021.

Deadlines are as follow:

Abstract submission: 1 October 2020

Paper submission: 9 October 2020

Author response: 6-8 January 2020

Notification of conditional accept / revise / reject: 20 January 2021

Revision submission (selected papers): 17 February 2021

Notification of conditional accept/reject for revisions: 3 March 2021

Shepherding decisions: 23 March 2021

Camera-ready submission: 26 March 2021


I will aim to start drafting the paper. EuroSys submission will be a lot of work, so we need to take this seriously.
