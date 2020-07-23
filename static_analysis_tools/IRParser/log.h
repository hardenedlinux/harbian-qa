#define RESET "\033[0m"
#define RED   "\033[31m"
#define GREEN "\033[32m"
#define BLUE  "\033[34m"

#define WARN  BLUE
#define SUCC  GREEN
#define FAIL  RED

#define WARN_LINE(s) WARN << s << "\n" << RESET
#define SUCC_LINE(s) SUCC << s << "\n" << RESET
#define FAIL_LINE(s) FAIL << s << "\n" << RESET
