/*
    This file is part of AcceSSL.

    Copyright 2011-2014 Marcin Gozdalik <gozdal@gmail.com>

    AcceSSL is free software; you can redistribute it and/or modify
    it under the terms of the GNU Affero General Public License as published by
    the Free Software Foundation; either version 3 of the License, or
    (at your option) any later version.

    AcceSSL is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU Affero General Public License for more details.

    You should have received a copy of the GNU Affero General Public License
    along with AcceSSL; if not, write to the Free Software
    Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA  02110-1301  USA
*/

#define BOOST_TEST_MODULE counted_tree

#include <utility>
#include <algorithm>
#include <iostream>

#include <boost/test/included/unit_test.hpp>

#include "counted_tree.hpp"

using namespace std;

BOOST_AUTO_TEST_CASE( empty_tree )
{
    counted_tree<int> empty;

    BOOST_CHECK( empty.size() == 0 );
    BOOST_CHECK( empty.empty() );
    BOOST_CHECK( empty.find_by_count(0) == empty.end() );
    BOOST_CHECK( empty.find_by_count(1) == empty.end() );
    BOOST_CHECK( empty.find_by_count(100) == empty.end() );
}

BOOST_AUTO_TEST_CASE( one_elem_tree )
{
    pair<int, size_t> elem(123, 10);
    vector<pair<int, size_t> > elems;
    elems.push_back(elem);

    counted_tree<int> one_elem(elems.begin(), elems.end());

    BOOST_CHECK( one_elem.size() == 1 );
    BOOST_CHECK( !one_elem.empty() );
    for (size_t i = 0; i < 10; i++) {
        counted_tree<int>::const_iterator iter = one_elem.find_by_count(i);
        BOOST_CHECK( *iter == 123 );
    }

    BOOST_CHECK(one_elem.find_by_count(10) == one_elem.end() );
}

BOOST_AUTO_TEST_CASE( two_elem_tree )
{
    pair<int, size_t> elem1(123, 3);
    pair<int, size_t> elem2(124, 7);
    vector<pair<int, size_t> > elems;
    elems.push_back(elem1);
    elems.push_back(elem2);

    counted_tree<int> two_elem(elems.begin(), elems.end());

    BOOST_CHECK( two_elem.size() == 2 );
    BOOST_CHECK( !two_elem.empty() );

    for (size_t i = 0; i < 3; i++) {
        counted_tree<int>::const_iterator iter = two_elem.find_by_count(i);
        BOOST_CHECK( *iter == 123 );
    }
    for (size_t i = 3; i < 10; i++) {
        counted_tree<int>::const_iterator iter = two_elem.find_by_count(i);
        BOOST_CHECK( *iter == 124 );
    }

    BOOST_CHECK(two_elem.find_by_count(10) == two_elem.end() );
}

BOOST_AUTO_TEST_CASE( n_elem_tree )
{
    size_t n = 9;
    vector<pair<int, size_t> > elems;

    for (size_t elem = 0; elem < n; elem++)
        elems.push_back(pair<int, size_t>(123+elem, (elem+1)*100));

    counted_tree<int> tree(elems.begin(), elems.end());

    BOOST_CHECK( tree.size() == n );
    BOOST_CHECK( !tree.empty() );

    size_t from = 0, to = 0;
    for (size_t elem = 0; elem < n; elem++) {
        from = to;
        to = from + (elem+1)*100;
        for (size_t i = from; i < to; i++) {
            counted_tree<int>::const_iterator iter = tree.find_by_count(i);
            BOOST_CHECK( *iter == ((int)elem+123) );
        }
    }

    BOOST_CHECK(tree.find_by_count(to) == tree.end() );
}

BOOST_AUTO_TEST_CASE( change_one_elem_tree )
{
    pair<int, size_t> elem(123, 10);
    vector<pair<int, size_t> > elems;
    elems.push_back(elem);

    counted_tree<int> one_elem(elems.begin(), elems.end());

    one_elem.change_count(one_elem.begin(), 5);

    for (size_t i = 0; i < 5; i++) {
        counted_tree<int>::const_iterator iter = one_elem.find_by_count(i);
        BOOST_CHECK( *iter == 123 );
    }

    BOOST_CHECK(one_elem.find_by_count(5) == one_elem.end() );
}

BOOST_AUTO_TEST_CASE( change_two_elem_tree )
{
    pair<int, size_t> elem1(123, 3);
    pair<int, size_t> elem2(124, 7);
    vector<pair<int, size_t> > elems;
    elems.push_back(elem1);
    elems.push_back(elem2);

    counted_tree<int> two_elem(elems.begin(), elems.end());

    two_elem.change_count(two_elem.begin(), 20);
    two_elem.change_count(two_elem.begin()+1, 30);

    for (size_t i = 0; i < 20; i++) {
        counted_tree<int>::const_iterator iter = two_elem.find_by_count(i);
        BOOST_CHECK( *iter == 123 );
    }
    for (size_t i = 20; i < 50; i++) {
        counted_tree<int>::const_iterator iter = two_elem.find_by_count(i);
        BOOST_CHECK( *iter == 124 );
    }

    BOOST_CHECK(two_elem.find_by_count(50) == two_elem.end() );
}


BOOST_AUTO_TEST_CASE( find_elem )
{
    size_t n = 9;
    vector<pair<int, size_t> > elems;

    for (size_t elem = 0; elem < n; elem++)
        elems.push_back(pair<int, size_t>(123+elem, (elem+1)*100));

    counted_tree<int> tree(elems.begin(), elems.end());

    for (size_t elem = 0; elem < n; elem++) {
        counted_tree<int>::const_iterator iter = std::find(tree.begin(), tree.end(), 123+elem);
        BOOST_CHECK( *iter == ((int)elem+123) );
    }
}

BOOST_AUTO_TEST_CASE( push_elem )
{
    counted_tree<int> tree;
    size_t n = 9;

    vector<int> steps;

    for (size_t i = 0; i < n; i++) {
        steps.push_back(10*(i+1));
        tree.push_back(123+i, 10*(i+1));

        size_t start = 0, end = 0;
        for (size_t j = 0; j < steps.size(); j++)
        {
            end = start + steps[j];
            for (size_t k = start; k < end; k++)
            {
                counted_tree<int>::const_iterator iter = tree.find_by_count(k);
                BOOST_CHECK( *iter == (123+(int)j) );
            }
            start = end;
        }
        BOOST_CHECK( tree.find_by_count(start) == tree.end());
    }
}

BOOST_AUTO_TEST_CASE( push_elems_change_to_zero )
{
    counted_tree<int> tree;
    size_t n = 9;

    vector<int> steps, order;

    for (size_t i = 0; i < n; i++) {
        steps.push_back(10*(i+1));
        tree.push_back(123+i, 10*(i+1));
        order.push_back(n-i-1);
    }

    for (size_t i = 0; i < n; i++) {
        counted_tree<int>::const_iterator elem = std::find(tree.begin(), tree.end(), 123+order[i]);
        tree.change_count(elem, 0); steps[order[i]] = 0;

        size_t start = 0, end = 0;
        for (size_t j = 0; j < steps.size(); j++)
        {
            end = start + steps[j];
            for (size_t k = start; k < end; k++)
            {
                counted_tree<int>::const_iterator iter = tree.find_by_count(k);
                BOOST_CHECK( *iter == (123+(int)j) );
            }
            start = end;
        }
    }
}

BOOST_AUTO_TEST_CASE( push_elems_total_count )
{
    counted_tree<int> tree;
    size_t n = 9;
    size_t total = 0;

    BOOST_CHECK( tree.total_count() == 0 );

    for (size_t i = 0; i < n; i++) {
        tree.push_back(123+i, 10*(i+1));
        total += 10*(i+1);
        BOOST_CHECK( tree.total_count() == total );
    }

    for (int i = n-1; i >= 0; i--) {
        counted_tree<int>::const_iterator elem = std::find(tree.begin(), tree.end(), 123+i);
        tree.change_count(elem, 0);
        total -= 10*(i+1);

        BOOST_CHECK( tree.total_count() == total );
    }

    BOOST_CHECK( tree.total_count() == 0 );
}
