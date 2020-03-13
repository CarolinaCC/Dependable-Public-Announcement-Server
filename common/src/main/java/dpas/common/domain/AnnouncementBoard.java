package dpas.common.domain;

import dpas.common.domain.exception.InvalidNumberOfPostsException;
import dpas.common.domain.exception.InvalidUserException;
import dpas.common.domain.exception.NullPostException;
import dpas.common.domain.exception.NullUserException;

import java.util.ArrayList;

public abstract class AnnouncementBoard {

    public ArrayList<Announcement> _posts;

    public abstract void post(User user, Announcement announcement) throws NullPostException, NullUserException, InvalidUserException;

    public ArrayList<Announcement> read(int number) throws InvalidNumberOfPostsException {
        if (number < 0 )
            throw new InvalidNumberOfPostsException();
        if (number == 0 || number >= _posts.size())
            return new ArrayList<>(_posts);
        return new ArrayList<Announcement>( _posts.subList(_posts.size()-number, _posts.size()));
    }

}
