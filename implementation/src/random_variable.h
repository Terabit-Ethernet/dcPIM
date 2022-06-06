#include "config.h"

struct CDFentry {
  double cdf_;
  double val_;
};

struct empirical_random_variable{
  double mean_flow_size;
  bool smooth;
  double minCDF_;		// min value of the CDF (default to 0)
  double maxCDF_;		// max value of the CDF (default to 1)
  int numEntry_;		// number of entries in the CDF table
  int maxEntry_;		// size of the CDF table (mem allocation)
  struct CDFentry* table_;	// CDF table of (val_, cdf_)
};

struct exp_random_variable {
	double avg_;
	double min_;
	double max_;
};

void init_empirical_random_variable(struct empirical_random_variable* r, char* filename, bool smooth);
void init_exp_random_variable(struct exp_random_variable* r, double avg);
int loadCDF(struct empirical_random_variable* r, char* filename);
int lookup(struct empirical_random_variable* r, double u);
double value_emp(struct empirical_random_variable* r);
double value_exp(struct exp_random_variable* r);
double interpolate(double x, double x1, double y1,
    double x2, double y2);
