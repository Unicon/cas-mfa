package net.unicon.cas.mfa.util;

import static org.junit.Assert.*;

import java.util.Arrays;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Set;

import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.JUnit4;

@RunWith(JUnit4.class)
public class MultiFactorUtilsTests {

    @Test
    public void testConversionOfSingleValueIntoCollection() {
        final Set<Object> set = MultiFactorUtils.convertValueToCollection("thisIsJustAValue");
        assertTrue(set.size() == 1);
    }

    @Test(expected = ClassCastException.class)
    public void testConversionOfNonObjectArrayIntoCollection() {
        final int[] array = {1, 2, 3};
        MultiFactorUtils.convertValueToCollection(array);
    }

    @Test
    public void testConversionOfArrayIntoCollection() {
        final Object[] array = {1, 2, 3};
        final Set<Object> set = MultiFactorUtils.convertValueToCollection(array);
        assertEquals(set.size(), 3);
    }

    @Test
    public void testConversionOfSetIntoCollection() {
        final Set<Object> set = MultiFactorUtils.convertValueToCollection(new HashSet(Arrays.asList("1", "2", "2")));
        assertEquals(set.size(), 2);
    }

    @Test(expected = UnsupportedOperationException.class)
    public void testConversionOfMapValuesIntoCollection() {
        MultiFactorUtils.convertValueToCollection(new HashMap());
    }
}
