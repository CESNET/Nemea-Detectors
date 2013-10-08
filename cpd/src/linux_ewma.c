/*
 * This source is taken from chromiumos sources:
 * lib/average.c
 */

#include <math.h>
#include "linux_ewma.h"

/**
 * DOC: Exponentially Weighted Moving Average (EWMA)
 *
 * These are generic functions for calculating Exponentially Weighted Moving
 * Averages (EWMA). We keep a structure with the EWMA parameters and a scaled
 * up internal representation of the average value to prevent rounding errors.
 * The factor for scaling up and the exponential weight (or decay rate) have to
 * be specified thru the init fuction. The structure should not be accessed
 * directly but only thru the helper functions.
 */

/**
 * ewma_init() - Initialize EWMA parameters
 * @avg: Average structure
 * @factor: Factor to use for the scaled up internal value. The maximum value
 *      of averages can be ULONG_MAX/(factor*weight). For performance reasons
 *      factor has to be a power of 2.
 * @weight: Exponential weight, or decay rate. This defines how fast the
 *      influence of older values decreases. For performance reasons weight has
 *      to be a power of 2.
 *
 * Initialize the EWMA parameters for a given struct ewma @avg.
 */
void ewma_init(struct ewma *avg, unsigned long factor, unsigned long weight)
{
        //WARN_ON(!is_power_of_2(weight) || !is_power_of_2(factor));

        avg->weight = log2(weight);
        avg->factor = log2(factor);
        avg->internal = 0;
}

/**
 * ewma_add() - Exponentially weighted moving average (EWMA)
 * @avg: Average structure
 * @val: Current value
 *
 * Add a sample to the average.
 */
struct ewma *ewma_add(struct ewma *avg, unsigned long val)
{
        avg->internal = avg->internal  ?
                (((avg->internal << avg->weight) - avg->internal) +
                        (val << avg->factor)) >> avg->weight :
                (val << avg->factor);
        return avg;
}

