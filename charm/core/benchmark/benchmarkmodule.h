/*
 * benchmarkmodule.h
 */
#ifndef Py_BENCHMARKMODULE_H_
#define Py_BENCHMARKMODULE_H_
#ifdef __cplusplus
extern "C" {
#endif

#include <Python.h>
#include <structmember.h>
#include <sys/time.h>

// set default if not passed in by compiler
//#ifndef BENCHMARK_ENABLED
//#define BENCHMARK_ENABLED 1
//#endif
//#define DEBUG   1
#define TRUE	1
#define FALSE	0

#ifdef DEBUG
#define debug(...)	printf("DEBUG: "__VA_ARGS__)
#else
#define debug(...)
#endif

#if PY_MAJOR_VERSION >= 3
	#define _PyLong_Check(o1) PyLong_Check(o1)
	#define ConvertToInt(o) PyLong_AsLong(o)
	#define PyToLongObj(o) PyLong_FromLong(o)
	/* check for both unicode and bytes objects */
	#define PyBytes_CharmCheck(obj) PyUnicode_Check(obj) || PyBytes_Check(obj)
	/* if unicode then add extra conversion step. two possibilities: unicode or bytes */
	#define PyBytes_ToString(a, obj)	\
if(PyUnicode_Check(obj)) { PyObject *_obj = PyUnicode_AsUTF8String(obj); a = PyBytes_AsString(_obj); Py_DECREF(_obj); }	\
else { a = PyBytes_AsString(obj); }
	#define PyBytes_ToString2(a, obj, tmp_obj)	\
if(PyBytes_Check(obj)) { a = PyBytes_AsString(obj); } \
else if(PyUnicode_Check(obj)) { tmp_obj = PyUnicode_AsUTF8String(obj); a = PyBytes_AsString(tmp_obj); }	\
else { tmp_obj = PyObject_Str(obj); a = PyBytes_AsString(tmp_obj); }
#else
	#define _PyLong_Check(o) (PyInt_Check(o) || PyLong_Check(o))
	#define ConvertToInt(o) PyInt_AsLong(o)
	#define PyToLongObj(o) PyInt_FromSize_t(o)
	#define PyUnicode_FromFormat PyString_FromFormat
    #define PyUnicode_FromString PyString_FromString
	/* treat everything as string in 2.x */
	#define PyBytes_CharmCheck(obj)	PyUnicode_Check(obj) || PyString_Check(obj)
	#define PyBytes_ToString(a, obj) a = PyString_AsString(obj);
#endif

#define BENCHMARK_MOD_NAME "charm.core.benchmark._C_API"

// define new benchmark type for benchmark module
PyTypeObject BenchmarkType;
// define new benchmark error type (will be used for notifying errors)
PyObject *BenchmarkError;
// define a macro to help determine whether an object is of benchmark type
#define PyBenchmark_Check(obj) PyObject_TypeCheck(obj, &BenchmarkType)
/* header file for benchmark module */
#define MAX_MEASURE 10
enum Measure {CPU_TIME = 0, REAL_TIME, NATIVE_TIME, ADDITION, SUBTRACTION, MULTIPLICATION, DIVISION, EXPONENTIATION, PAIRINGS, GRANULAR, NONE};
typedef enum Measure MeasureType;
#define _CPUTIME_OPT 	"CpuTime"
#define _REALTIME_OPT 	"RealTime"
#define _ADD_OPT		"Add"
#define _SUB_OPT		"Sub"
#define _MUL_OPT		"Mul"
#define _DIV_OPT		"Div"
#define _EXP_OPT		"Exp"
#define _PAIR_OPT		"Pair"
#define _GRAN_OPT		"Granular"

typedef struct {
	PyObject_HEAD

	struct timeval start_time, stop_time, native_time; // track real time
	clock_t start_clock, stop_clock; // track cpu time
	// Operations *op_ptr; // track various operations
	int op_add, op_sub, op_mult, op_div;
	int op_exp, op_pair;
	double native_time_ms, cpu_time_ms, real_time_ms;
	int num_options; // track num options for a particular benchmark
	MeasureType options_selected[MAX_MEASURE]; // measurement options selected
	int cpu_option, native_option, real_option, granular_option;
	int identifier;
	int bench_initialized;
	void *data_ptr;
	void (*gran_init)(void);
} Benchmark;

// PyMethodDef Benchmark_methods[];
PyObject *Benchmark_new(PyTypeObject *type, PyObject *args, PyObject *kwds);
void Benchmark_dealloc(Benchmark *self);
int Benchmark_init(Benchmark *self, PyObject *args, PyObject *kwds);
PyObject *Benchmark_print(Benchmark *self);
PyObject *GetResults(Benchmark *self);
PyObject *GetResultsWithPair(Benchmark *self);
PyObject *Retrieve_result(Benchmark *self, char *option);

/* c api functions */
#define PyBenchmark_Start 		  0
#define PyBenchmark_End 		  1
#define PyBenchmark_Update		  2
#define PyBenchmark_StartT		  3
#define PyBenchmark_StopT	      4
#define PyBenchmark_Clear		  5

/* total number of C api pointers? */
#define PyBenchmark_API_pointers 6

#ifdef BENCHMARK_ENABLED
#define UPDATE_BENCHMARK(option, bench)   \
	if(bench->bench_initialized) {	   \
	PyUpdateBenchmark(option, bench); }

#else
#define UPDATE_BENCHMARK(option, bench) /* ... */
#endif

#ifdef BENCHMARK_MODULE
/* This section is used when compiling benchmarkmodule.c */
static int PyStartBenchmark(Benchmark *data, PyObject *opList, int opListSize);
static int PyEndBenchmark(Benchmark *data);
static int PyUpdateBenchmark(MeasureType option, Benchmark *data);
static int PyStartTBenchmark(MeasureType option, Benchmark *data);
static int PyStopTBenchmark(MeasureType option, Benchmark *data);
static int PyClearBenchmark(Benchmark *data);

#else

/* This section is used in modules that use benchmarkmodule's API
 * e.g. pairingmath, integermath, etc.
 */
static void **PyBenchmark_API;

#define PyStartBenchmark (*(int (*)(Benchmark *data, PyObject *opList, int opListSize)) PyBenchmark_API[PyBenchmark_Start])
#define PyEndBenchmark (*(int (*)(Benchmark *data)) PyBenchmark_API[PyBenchmark_End])
#define PyUpdateBenchmark (*(int (*)(MeasureType option, Benchmark *data)) PyBenchmark_API[PyBenchmark_Update])
#define PyStartTBenchmark (*(int (*)(MeasureType option, Benchmark *data)) PyBenchmark_API[PyBenchmark_StartT])
#define PyStopTBenchmark (*(int (*)(MeasureType option, Benchmark *data)) PyBenchmark_API[PyBenchmark_StopT])
#define PyClearBenchmark (*(int (*)(Benchmark *data)) PyBenchmark_API[PyBenchmark_Clear])

/* start - api helper functions */
#define InitBenchmark_CAPI(func_name, b, id) \
PyObject *func_name(PyObject *self, PyObject *args) { 	\
	debug("%s: bench init: '%i'\n", __FUNCTION__, b->bench_initialized); \
	if(b->bench_initialized == FALSE) {   		\
		b->bench_initialized = TRUE;		\
		b->identifier = id;				\
		debug("%s: bench id set: '%i'\n", __FUNCTION__, b->identifier); 	\
		debug("Initialized benchmark object.\n");	\
		PyObject *result = Py_BuildValue("i", id); \
		return result; }	\
	debug("Benchmark already initialized.\n");	\
	Py_RETURN_FALSE;	}

#define StartBenchmark_CAPI(func_name, b) 	\
PyObject *func_name(PyObject *self, PyObject *args) { \
	PyObject *list = NULL; int id = -1;			\
	if(PyArg_ParseTuple(args, "iO", &id, &list)) {		\
		if(b->bench_initialized == TRUE && id == b->identifier) { \
			debug("%s: bench id: '%i'\n", __FUNCTION__, b->identifier); 	\
			size_t size = PyList_Size(list);	\
			PyStartBenchmark(b, list, size);	\
		debug("list size => %zd\n", size);		\
		debug("benchmark enabled and initialized!\n");\
		Py_RETURN_TRUE;  }				\
		Py_RETURN_FALSE; 	}			\
	return NULL;	}

#define EndBenchmark_CAPI(func_name, b)		\
PyObject *func_name(PyObject *self, PyObject *args) { \
	int id = -1;					\
	if(PyArg_ParseTuple(args, "i", &id)) {		\
		debug("%s: bench init: '%i'\n", __FUNCTION__, b->bench_initialized); \
		debug("%s: bench id: '%i'\n", __FUNCTION__, b->identifier); \
		if(b->bench_initialized == TRUE && id == b->identifier) {		\
			PyEndBenchmark(b);		\
			b->bench_initialized = FALSE; \
			b->identifier = id;	\
			debug("%s: bench id: '%i'\n", __FUNCTION__, b->identifier); 	\
			Py_RETURN_TRUE;		}	\
	debug("Invalid benchmark identifier.\n"); } 	\
	Py_RETURN_FALSE;			}

#define GetBenchmark_CAPI(func_name, b) \
PyObject *func_name(PyObject *self, PyObject *args) { \
	int id = -1;					\
	char *opt = NULL;			\
	if(PyArg_ParseTuple(args, "i|s", &id, &opt)) { \
		return Retrieve_result(b, opt); \
		}		\
	Py_RETURN_FALSE;	}

#define GetAllBenchmarks_CAPI(func_name, b, getResultFunc)	\
PyObject *func_name(PyObject *self, PyObject *args) { \
	int id = -1;					\
	if(PyArg_ParseTuple(args, "i", &id)) {		\
		debug("%s: bench id: '%i', id: '%d'\n", __FUNCTION__, b->identifier, id); \
		if(id == b->identifier)		\
			return getResultFunc(b);	\
	debug("Invalid benchmark identifier.\n"); }	\
	Py_RETURN_FALSE;	}

#define ClearBenchmarks_CAPI(func_name, b) \
PyObject *func_name(PyObject *self, PyObject *args) { \
	int id = -1;					\
	if(PyArg_ParseTuple(args, "i", &id)) {		\
		if(id == b->identifier)	{	\
			PyClearBenchmark(b);	\
			debug("Benchmark object cleared!\n");	\
			Py_RETURN_TRUE;    } 		\
	debug("Invalid benchmark idenifier.\n"); }	\
	Py_RETURN_FALSE;	}

#define ADD_BENCHMARK_OPTIONS(m)		\
	PyModule_AddStringConstant(m, "CpuTime", "CpuTime");		\
	PyModule_AddStringConstant(m, "RealTime", "RealTime");		\
	PyModule_AddStringConstant(m, "Add", "Add");			\
	PyModule_AddStringConstant(m, "Sub", "Sub");		\
	PyModule_AddStringConstant(m, "Mul", "Mul");		\
	PyModule_AddStringConstant(m, "Div", "Div");			\
	PyModule_AddStringConstant(m, "Exp", "Exp");

/* end - api helper functions */

static int import_benchmark(void)
{
	PyBenchmark_API = (void **) PyCapsule_Import(BENCHMARK_MOD_NAME, 1);
	return (PyBenchmark_API != NULL) ? 0 : -1;
}

#endif

#ifdef __cplusplus
}
#endif

#endif /* PY_BENCHMARK_H_ */
