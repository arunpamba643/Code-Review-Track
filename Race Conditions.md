# Race Condition — SAST Description
## Description:
A Race Condition occurs when two or more threads or processes access shared resources concurrently, and the outcome depends on the timing of their execution. Insecure handling can lead to inconsistent state, data corruption, privilege escalation, or bypassing of critical logic like authentication or authorization.

## How SAST Detects Race Conditions:
SAST tools detect race conditions by identifying:\
Shared resources accessed without proper synchronization (e.g., file, memory, database record).\
Critical sections of code missing locks, atomic operations, or thread-safe practices.\
Non-atomic check-then-act patterns (TOCTOU: Time-Of-Check to Time-Of-Use issues).\
File or object creation that lacks exclusive access or permission validation.

## Mitigation:
Use proper locking mechanisms (synchronized, mutex, semaphore, atomic variables).\
Avoid shared mutable state where possible.\
Prefer thread-safe libraries or immutable objects.\
For filesystem operations, use secure APIs (e.g., open() with O_CREAT | O_EXCL).\
Implement transactional logic for operations that span multiple steps.\
Use SemaphoreSlim when multiple threads need controlled access to a resource\
Interlocked provides atomic operations, ensuring thread-safe modifications to shared resources 
without lock\
Mutex ensures only one thread across multiple processes can access a resource.\
Monitor provides finer control over locking, allowing timeout handling\
Use lock to ensure only one thread accesses the critical section at a time.


# Vulnerable Code:
public class BankAccount
{
 private int balance = 1000;
 public void Withdraw(int amount)
 {
 if (balance >= amount) // Another thread can modify `balance` before this executes!
 {
 balance -= amount; // Race condition occurs here!
 Console.WriteLine($"Withdrawal successful. Remaining balance: {balance}");
 }
 else
 {
 Console.WriteLine("Insufficient funds.");
 }
 }
}
