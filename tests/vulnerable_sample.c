#include <stdio.h>
#include <stdlib.h>
#include <string.h>

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

void null_dereference() {
    int *p = NULL;
    // CWE-476: Null Pointer Dereference
    int x = *p;
}

void memory_leak() {
    // CWE-401: Memory Leak (if implemented in AST)
    int *leak = malloc(100);
    // No free(leak)
}

void weak_random() {
    // CWE-338: Weak Random Number Generator
    int r = rand();
}

int main(int argc, char **argv) {
    if (argc > 1) {
        process_data(argv[1]);
        command_execution(argv[1]);
    }
    
    memory_issues();
    return_stack_address();
    uninitialized_variable();
    weak_random();
    
    return 0;
}
