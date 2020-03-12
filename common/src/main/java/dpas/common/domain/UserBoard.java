package dpas.common.domain;

import dpas.common.domain.exception.InvalidNumberOfPostsException;
import dpas.common.domain.exception.InvalidUserException;
import dpas.common.domain.exception.NullPostException;
import dpas.common.domain.exception.NullUserException;

import java.util.ArrayList;

public class UserBoard implements AnnouncementBoard {
    public ArrayList<Announcement> _posts;
    public User _owner;

    @Override

    public void post(User user, Announcement announcement) throws NullPostException, NullUserException, InvalidUserException {
        checkArguments(user, announcement);
        _posts.add(announcement);
    }

    public void checkArguments(User user, Announcement post) throws NullUserException, NullPostException, InvalidUserException {
        if (user == null) {
            throw new NullUserException();
        }
        if (post == null) {
            throw new NullPostException();
        }
        if (user != _owner) {
            throw new InvalidUserException();
        }
    }

    @Override
    public ArrayList<Announcement> read(int number) throws InvalidNumberOfPostsException {
        if (number <= 0 || number > _posts.size())
            throw new InvalidNumberOfPostsException();
        return new ArrayList<Announcement>( _posts.subList(_posts.size()-number, _posts.size()));
    }
}
