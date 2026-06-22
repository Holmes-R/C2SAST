#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

// CWE-798: Hardcoded Credentials
const char* api_key = "secret_12345";

void process_data(char *input) {
    char buffer[50];
    
    // CWE-120: Buffer Overflow
    strcpy(buffer, input);
    
    // CWE-134: Format String Vulnerability
    printf(input);
    
    // CWE-120: Buffer Overflow (scanf)
    char buf[10];
    scanf("%s", buf);

    // CWE-22: Path Traversal
    fopen(input, "r");

    // CWE-377: Insecure Temporary File
    char tmpname[256];
    tmpnam(tmpname);
}

void memory_issues() {
    // CWE-190: Integer Overflow in Allocation
    int count = 1000000;
    int *array = malloc(count * count * sizeof(int)); // Overflow possible
    
    if (!array) return;
    
    // CWE-415: Double Free
    free(array);
    free(array); 
    
    // CWE-416: Use-After-Free
    int *ptr = malloc(sizeof(int));
    *ptr = 10;
    free(ptr);
    int val = *ptr; // Use after free
}

void command_execution(char *cmd) {
    // CWE-78: Command Injection
    system(cmd);
}

int* return_stack_address() {
    int local_var = 42;
    // CWE-562: Return of Stack Address
    return &local_var;
}

void uninitialized_variable() {
    // CWE-457: Use of Uninitialized Variable
    int uninit;
    int b = uninit + 5; 
}

void other_issues() {
    // CWE-676: Potentially Dangerous Function
    char str[] = "hello,world";
    char *token = strtok(str, ",");

    // CWE-330: Insufficiently Random Values (constant seed)
    srand(42);

    // CWE-338: Weak Random Number Generator
    int r = rand();

    // CWE-369: Divide By Zero
    int x = 100;
    int y = x / r; // denominator is variable, could be zero

    // CWE-558: Use of getlogin()
    char *user = getlogin();

    // CWE-789: Uncontrolled Memory Allocation (size from variable)
    int size = x;
    int *big = malloc(size);

    // CWE-467: sizeof on pointer type
    int *arr = malloc(10 * sizeof(arr)); // should be sizeof(*arr)
}

void switch_issues(int cmd) {
    // CWE-478: Missing Default Case
    switch (cmd) {
        case 1:
            break;
    }

    // CWE-484: Omitted Break in Switch Case
    switch (cmd) {
        case 1:
            process_data("hello");
            // missing break
        case 2:
            break;
    }
}

void fixed_address() {
    // CWE-587: Assignment of Fixed Address to Pointer
    int *dev_ptr = (int*)0x10000000;
}

void assignment_in_condition(int x) {
    // CWE-480: Assignment in Condition
    if (x = 5) {
        process_data("test");
    }
}

int main(int argc, char **argv) {
    if (argc > 1) {
        process_data(argv[1]);
        command_execution(argv[1]);
    }
    
    memory_issues();
    return_stack_address();
    uninitialized_variable();
    other_issues();
    switch_issues(argc);
    fixed_address();
    assignment_in_condition(argc);
    
    return 0;
}
