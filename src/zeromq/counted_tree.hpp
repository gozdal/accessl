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

#ifndef _COUNTED_TREE_HPP_
#define _COUNTED_TREE_HPP_

#include <vector>
#include <utility>
#include <algorithm>
#include <iterator>
#include <cassert>

/*
we'll simplify the tree but adding extra constraints:
 - you can only push back, not in front
 - you can't erase an element - you can only set its count 0
*/

/*
template <class T, class A = std::allocator<T> >
class X {
public:
    typedef A allocator_type;
    typedef A::value_type value_type;
    typedef A::reference reference;
    typedef A::const_reference const_reference;
    typedef A::difference_type difference_type;
    typedef A::size_type size_type;

    class iterator {
    public:
        typedef A::difference_type difference_type;
        typedef A::value_type value_type;
        typedef A::reference reference;
        typedef A::pointer pointer;
        typedef std::random_access_iterator_tag iterator_category

        iterator();
        iterator(const iterator&);
        ~iterator();

        iterator& operator=(const iterator&);
        bool operator==(const iterator&) const;
        bool operator!=(const iterator&) const;

        iterator& operator++();
        iterator operator++(int); //optional
        iterator& operator--(); //optional
        iterator operator--(int); //optional
        iterator& operator+=(size_type); //optional
        iterator operator+(size_type) const; //optional
        friend iterator operator+(size_type, const iterator&) //optional
        iterator& operator-=(size_type); //optional
        iterator operator-(size_type) const; //optional
        difference_type operator-(iterator) const; //optional

        reference operator*() const;
        pointer operator->() const;
        reference operator[](size_type) const; //optional
    };
    class const_iterator {
    public:
        typedef A::difference_type difference_type;
        typedef A::value_type value_type;
        typedef A::reference const_reference;
        typedef A::pointer const_pointer;
        typedef std::random_access_iterator_tag iterator_category

        const_iterator ();
        const_iterator (const const_iterator&);
        const_iterator (const iterator&);
        ~const_iterator();

        const_iterator& operator=(const const_iterator&);
        bool operator==(const const_iterator&) const;
        bool operator!=(const const_iterator&) const;
        bool operator<(const const_iterator&) const; //optional
        bool operator>(const const_iterator&) const; //optional
        bool operator<=(const const_iterator&) const; //optional
        bool operator>=(const const_iterator&) const; //optional

        const_iterator& operator++();
        const_iterator operator++(int); //optional
        const_iterator& operator--(); //optional
        const_iterator operator--(int); //optional
        const_iterator& operator+=(size_type); //optional
        const_iterator operator+(size_type) const; //optional
        friend const_iterator operator+(size_type, const const_iterator&) //optional
        const_iterator& operator-=(size_type); //optional
        const_iterator operator-(size_type) const; //optional
        difference_type operator-(const_iterator) const; //optional

        const_reference operator*() const;
        const_pointer operator->() const;
        const_reference operator[](size_type) const; //optional
    };

    typedef std::reverse_iterator<iterator> reverse_iterator //optional
    typedef std::reverse_iterator<const_iterator> const_reverse_iterator //optional

    X();
    X(const X&);
    ~X();

    X& operator=(const X&);
    bool operator==(const X&) const;
    bool operator!=(const X&) const;
    bool operator<(const X&) const; //optional
    bool operator>(const X&) const; //optional
    bool operator<=(const X&) const; //optional
    bool operator>=(const X&) const; //optional

    iterator begin();
    const_iterator begin() const;
    const_iterator cbegin() const;
    iterator end();
    const_iterator end() const;
    const_iterator cend() const;
    reverse_iterator rbegin(); //optional
    const_reverse_iterator rbegin() const; //optional
    const_reverse_iterator crbegin() const; //optional
    reverse_iterator rend(); //optional
    const_reverse_iterator rend() const; //optional
    const_reverse_iterator crend() const; //optional

    reference front(); //optional
    const_reference front() const; //optional
    reference back(); //optional
    const_reference back() const; //optional
    template<class ...Args>
    void emplace_front(Args...); //optional
    template<class ...Args>
    void emplace_back(Args...); //optional
    void push_front(const T&); //optional
    void push_front(T&&); //optional
    void push_back(const T&); //optional
    void push_back(T&&); //optional
    void pop_front(); //optional
    void pop_back(); //optional
    reference operator[](size_type); //optional
    const_reference operator[](size_type) const; //optional
    reference at(size_type); //optional
    const_reference at(size_type) const; //optional

    template<class ...Args>
    iterator emplace(const_iterator, Args...); //optional
    iterator insert(const_iterator, const T&); //optional
    iterator insert(const_iterator, T&&); //optional
    iterator insert(const_iterator, size_type, T&); //optional
    template<class iter>
    iterator insert(const_iterator, iter, iter); //optional
    iterator insert(const_iterator, std::initializer_list<T>); //optional
    iterator erase(const_iterator); //optional
    iterator erase(const_iterator, const_iterator); //optional
    void clear(); //optional
    template<class iter>
    void assign(iter, iter); //optional
    void assign(std::initializer_list<T>); //optional
    void assign(size_type, const T&); //optional

    void swap(const X&);
    size_type size();
    size_type max_size();
    bool empty();

    A get_allocator(); //optional
}
*/

template <class T, class A = std::allocator<T> >
class counted_tree {
protected:
    typedef std::vector<T> container;
    typedef std::vector<size_t> container_size_t;

public:
    typedef A allocator_type;
    typedef typename A::value_type value_type;
    typedef typename A::reference reference;
    typedef typename A::const_reference const_reference;
    typedef typename A::difference_type difference_type;
    typedef typename A::size_type size_type;

    typedef typename container::iterator iterator;
    typedef typename container::const_iterator const_iterator;
    typedef typename container::reverse_iterator reverse_iterator;
    typedef typename container::const_reverse_iterator const_reverse_iterator;

    counted_tree()
    { }

    template <class Iter>
    counted_tree(Iter it, Iter end) { build(it, end); }

    counted_tree(const counted_tree& other) :
        elems(other.elems),
        sums(other.sums)
    { }

    ~counted_tree() { }

    counted_tree& operator=(const counted_tree& other)
    {
        counted_tree tmp(other);
        swap(tmp);
        return *this;
    }

    bool operator==(const counted_tree& other) const { return elems == other.elems; }
    bool operator!=(const counted_tree& other) const { return elems != other.elems; }

    const_iterator begin() const { return elems.begin(); }
    const_iterator end() const { return elems.end(); }

    const_reference front() const { return elems.front(); }
    const_reference back() const { return elems.back(); }
    void push_back(const T& elem, size_t count)
    {
        container_size_t::iterator leaf_counts = leafs_begin(sums.begin());
        container_size_t::iterator leaf_counts_end = leaf_counts;
        std::advance(leaf_counts_end, size());
        container_size_t counts_copy(leaf_counts, leaf_counts_end);
        counts_copy.push_back(count);

        elems.push_back(elem);

        copy_leaf_sums(counts_copy.begin(), counts_copy.end());
        calc_partial_sums();
    }
    const_reference operator[](size_type s) const { return elems[s]; }
    const_reference at(size_type s) const { return elems.at(s); }

    void swap(counted_tree& other)
    {
        elems.swap(other.elems);
        sums.swap(other.sums);
    }

    size_type size() const { return elems.size(); }
    size_type max_size() const { return elems.max_size(); }
    bool empty() const { return elems.empty(); }

    const_iterator find_by_count(size_t count) const
    {
        size_t i = find_index_by_count(count);
        size_t partial_sums_size = sums.size() / 2;

        if (i == (size_t)-1)
            return end();

        return elems.begin() + (i - partial_sums_size);
    }

    void change_count(const_iterator iter, size_t count)
    {
        size_t leaf_index = std::distance(begin(), iter);
        size_t partial_sums_size = sums.size() / 2;
        size_t sum_index = partial_sums_size + leaf_index;

        size_t old_count = sums[sum_index];

        ssize_t diff = count - old_count;

        sums[sum_index] += diff;

        while (parent(sum_index) != sum_index) {
            sum_index = parent(sum_index);
            sums[sum_index] += diff;
        }
    }

    size_t total_count() const
    {
        if (empty())
            return 0;
        else
            return sums[0];
    }

private:
    container elems;
    container_size_t sums;

    static size_t smallest_power_of_2(size_t i)
    {
        size_t ret = 1;
        while (ret < i)
            ret <<= 1;
        return ret;
    }

    static size_t parent(size_t node)
    {
        if (node == 0)
            return 0;
        return ((node + 1) >> 1) - 1;
    }

    static size_t left(size_t node)
    {
        return ((node + 1) << 1) - 1;
    }

    static size_t right(size_t node)
    {
        return left(node) + 1;
    }

    size_t total_leafs_size() const
    {
        return smallest_power_of_2(elems.size());
    }

    size_t total_partial_size() const
    {
        return total_leafs_size() - 1;
    }

    size_t total_tree_size() const
    {
        return total_leafs_size() + total_partial_size();
    }

    template <class Iter>
    Iter leafs_begin(Iter it) const
    {
        std::advance(it, total_partial_size());
        return it;
    }

    template <class Iter>
    void copy_leaf_sums(Iter it, Iter end)
    {
        assert((size_t)std::distance(it, end) == elems.size());

        sums.resize(total_tree_size());
        container_size_t::iterator leafs_end = leafs_begin(sums.begin());
        std::advance(leafs_end, elems.size());
        // backwards to allow for moving leaf sums in sums when resizing to bigger tree
        std::copy_backward(it, end, leafs_end);
    }

    void calc_partial_sums()
    {
        for (size_t i = total_tree_size() - 1; i > 0; i -= 2) {
            sums[parent(i)] = sums[i] + sums[i-1];
        }
    }

    void correct_sums(size_t elem)
    {
        while (elem != 0) {
            elem = parent(elem);
            sums[elem] = sums[left(elem)] + sums[right(elem)];
        };
    }

    template <class Iter>
    void build(Iter it, Iter end)
    {
        container_size_t counts;
        elems.clear();

        while (it != end) {
            elems.push_back(it->first);
            counts.push_back(it->second);
            ++it;
        }

        copy_leaf_sums(counts.begin(), counts.end());
        calc_partial_sums();
    }

    template <class LeafIter, class CountIter>
    void build(LeafIter leafit, LeafIter leafend, CountIter countit, CountIter countend)
    {
        container_size_t counts;
        elems.clear();

        while (leafit != leafend && countit != countend) {
            elems.push_back(*leafit);
            counts.push_back(*countit);

            ++leafit;
            ++countit;
        }

        copy_leaf_sums(counts.begin(), counts.end());
        calc_partial_sums();
    }

    size_t find_index_by_count(size_t count) const
    {
        size_t i = 0;
        size_t partial_sums_size = sums.size() / 2;

        if (sums.empty() || count >= sums[0])
            return (size_t)-1;

        while (i < partial_sums_size) {
            if (count < sums[left(i)])
                i = left(i);
            else {
                count -= sums[left(i)];
                i = right(i);
            }
        };

        return i;
    }

};

#endif // _COUNTED_TREE_HPP_

