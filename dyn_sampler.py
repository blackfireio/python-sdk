"""
Dynamic sampling module for APM traces.
Different sampling strategies can be supported by respecting the `_BaseSampler` interface.

Currently, the default strategy is `_EWMASampler`, which uses an Exponentially Weighted
Moving Average to prioritize error traces over successful ones while adhering to a global 
sampling rate and ensuring no success starvation happens.
"""

import random

from blackfire.utils import get_logger

log = get_logger(__name__)

class _BaseSampler(object):
    """Base class for all sampling strategies."""
    def should_keep(self, **kwargs):
        pass
    
    def reset(self):
        """Reset sampler state (optional for stateless samplers)."""
        pass

class _EWMASampler(_BaseSampler):
    """
    Exponentially Weighted Moving Average sampler for error prioritization.
    Error/Outliers are sampled more aggressively than successes, returns the adjusted
    sampling rate for the current trace.

    There are lots of ways to implement dynamic sampling, but this one uses O(1)
    memory and adapts quickly to traffic changes by exponentially decaying the 
    error fraction with time and plus still allowing some successes to be sampled.

    The core idea is as following:
        • when errors are rare (pE ≤ R): keep all errors (sE=1) and let successes fill the rest;
        • when errors dominate (pE > R): throttle errors to use ~R and give successes only the floor.
    """
    def __init__(self, initial_err_fraction=0.001, beta=0.01, success_floor=0.05):
        self._pE = initial_err_fraction
        self._beta = beta  # EWMA smoothing factor
        self._success_floor = success_floor  # Minimum success sampling rate
    
    def should_keep(self, is_error, sample_rate, **kwargs):
        """
        EWMA-based sampling decision.
        
        Args:
            is_error (bool): Whether this trace represents an error
            sample_rate (float): Target overall sampling rate
            **kwargs: Ignored (for interface compatibility)
        
        Returns:
            tuple: (keep: bool, effective_rate: float)
        """
        # compute current traffic's error/success fraction's
        pS = 1.0 - self._pE  # success fraction
        
        # Error sampling rate: keep all if pE==0, else throttle to R/pE (cap at 1)
        sE = 1.0 if self._pE == 0 else min(1.0, sample_rate / self._pE)
        
        # Success sampling rate: use leftover budget
        sS = 1.0 if pS == 0 else min(1.0, (sample_rate - self._pE * sE) / pS)
        
        # prevent success starvation, always send some successes, this might overshoot
        # the budget a bit by (+sS_floor), but it is better than starving successes
        sS = max(sS, self._success_floor)
        
        # Decide whether to keep this trace
        eff_rate = sE if is_error else sS
        keep = random.random() < eff_rate
        
        # Update EWMA of error fraction
        # This might be a bit counterintuitive, but in fact all we do is to get 
        # weighted average of the old error fraction(self._PE) and the new one(beta * is_error)
        # beta controls how fast we adapt to changes, higher means faster adaptation.
        # This way, newer errors will have more weight, but we still keep some history.
        self._pE = (1 - self._beta) * self._pE + self._beta * (1 if is_error else 0)

        log.debug(
            "EWMA sampling: error=%s, pE=%.3f, sE=%.3f, sS=%.3f, eff_rate=%.3f, keep=%s", 
            is_error, self._pE, sE, sS, eff_rate, keep
        )
        
        return keep, eff_rate
    
    def reset(self):
        """Reset error fraction to initial value."""
        self._pE = 0.001

# Default to EWMA sampler, set_sampler() can be implemented to allow changing sampling 
# strategy in the future
_sampler = _EWMASampler()

def should_keep(*args, **kwargs):
    return _sampler.should_keep(*args, **kwargs)

def reset():
    _sampler.reset()
