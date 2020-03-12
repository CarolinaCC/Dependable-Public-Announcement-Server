package dpas.common.domain;

import dpas.common.domain.exception.InvalidNumberOfPostsException;
import dpas.common.domain.exception.InvalidUserException;
import dpas.common.domain.exception.NullPostException;
import dpas.common.domain.exception.NullUserException;

import java.util.ArrayList;

public class UserBoard implements AnnouncementBoard {
    //FIXME do we wanna keep the _ before the name like in the rest of the code (I just started doing it as a joke)
    public ArrayList<Announcement> posts;
    public User owner;

    @Override

    public void post(User user, Announcement announcement) throws NullPostException, NullUserException, InvalidUserException {
        checkArguments(user, announcement);
        posts.add(announcement);
    }

    public void checkArguments(User user, Announcement post) throws NullUserException, NullPostException, InvalidUserException {
        if (user == null) {
            throw new NullUserException();
        }
        if (post == null) {
            throw new NullPostException();
        }
        //FIXME shouldn't it be if user != owner ?
        if (user == owner) {
            throw new InvalidUserException();
        }
    }

    @Override
    public Announcement[] read(int number) throws InvalidNumberOfPostsException {
        if (number <= 0 || number > posts.size())
            throw new InvalidNumberOfPostsException();
        return (Announcement[]) posts.subList(posts.size()-number, posts.size()).toArray();
    }
}
